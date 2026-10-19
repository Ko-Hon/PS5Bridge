package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type filterJump struct {
	index  int
	label  string
	branch bool
}

func captureFilters(cfg configuration, mac net.HardwareAddr) []syscall.BpfInsn {
	drop := []syscall.BpfInsn{{Code: syscall.BPF_RET | syscall.BPF_K, K: 0}}
	if len(mac) != 6 || len(cfg.clients()) > 8 {
		return drop
	}
	var code []syscall.BpfInsn
	labels := map[string]int{}
	var jumps []filterJump
	load := func(size uint16, offset uint32) {
		code = append(code, syscall.BpfInsn{Code: syscall.BPF_LD | size | syscall.BPF_ABS, K: offset})
	}
	jump := func(value uint32, label string, whenEqual bool) {
		jumps = append(jumps, filterJump{len(code), label, whenEqual})
		code = append(code, syscall.BpfInsn{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: value})
	}
	goTo := func(label string) {
		jumps = append(jumps, filterJump{len(code), label, true})
		code = append(code, syscall.BpfInsn{Code: syscall.BPF_JMP | syscall.BPF_JA})
	}
	load(syscall.BPF_H, 12)
	jump(0x0800, "v4", true)
	jump(0x86dd, "v6", true)
	goTo("drop")
	labels["v4"] = len(code)
	load(syscall.BPF_W, 0)
	jump(binary.BigEndian.Uint32(mac[:4]), "drop", false)
	load(syscall.BPF_H, 4)
	jump(uint32(binary.BigEndian.Uint16(mac[4:])), "drop", false)
	load(syscall.BPF_W, 26)
	for _, text := range cfg.clients() {
		ip := net.ParseIP(text).To4()
		if ip == nil {
			return drop
		}
		jump(binary.BigEndian.Uint32(ip), "accept", true)
	}
	goTo("drop")
	labels["v6"] = len(code)
	if cfg.IPv6 {
		if cfg.Router.Is6() {
			load(syscall.BPF_B, 20)
			jump(58, "selectedPeers", false)
			load(syscall.BPF_B, 54)
			jump(135, "dadTarget", true)
			jump(136, "dadTarget", true)
			goTo("selectedPeers")
			labels["dadTarget"] = len(code)
			address := cfg.Router.AsSlice()
			for i := 0; i < 4; i++ {
				load(syscall.BPF_W, uint32(62+4*i))
				jump(binary.BigEndian.Uint32(address[4*i:]), "selectedPeers", false)
			}
			goTo("accept")
			labels["selectedPeers"] = len(code)
		}
		for i, seed := range cfg.Peers {
			m, err := net.ParseMAC(seed.MAC)
			if err != nil || len(m) != 6 {
				return drop
			}
			next := fmt.Sprintf("mac%d", i)
			load(syscall.BPF_W, 6)
			jump(binary.BigEndian.Uint32(m[:4]), next, false)
			load(syscall.BPF_H, 10)
			jump(uint32(binary.BigEndian.Uint16(m[4:])), "accept", true)
			labels[next] = len(code)
		}
	}
	goTo("drop")
	labels["accept"] = len(code)
	code = append(code, syscall.BpfInsn{Code: syscall.BPF_RET | syscall.BPF_K, K: 65535})
	labels["drop"] = len(code)
	code = append(code, drop...)
	for _, j := range jumps {
		skip := labels[j.label] - j.index - 1
		if skip < 0 || skip > 255 {
			return drop
		}
		if code[j.index].Code == syscall.BPF_JMP|syscall.BPF_JA {
			code[j.index].K = uint32(skip)
		} else if j.branch {
			code[j.index].Jt = uint8(skip)
		} else {
			code[j.index].Jf = uint8(skip)
		}
	}
	return code
}

func captureFilter(client net.IP, mac net.HardwareAddr) []syscall.BpfInsn {
	return captureFilters(configuration{Client: client.String()}, mac)
}

func parseLANMAC(text string) (net.HardwareAddr, error) {
	parts := strings.Split(text, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid MAC")
	}
	mac := make(net.HardwareAddr, 6)
	for i, part := range parts {
		if len(part) < 1 || len(part) > 2 {
			return nil, fmt.Errorf("invalid MAC")
		}
		v, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, err
		}
		mac[i] = byte(v)
	}
	return mac, nil
}

func localTool(path string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, _ := exec.CommandContext(ctx, path, args...).Output()
	return string(b)
}

func prepareIPv6(cfg *configuration, lan *net.Interface) error {
	if !cfg.IPv6 {
		return nil
	}
	addrs, err := lan.Addrs()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, addr := range addrs {
		p, err := netip.ParsePrefix(addr.String())
		if err == nil && p.Addr().Is6() && p.Addr().IsGlobalUnicast() && p.Bits() == 64 {
			text := p.Masked().String()
			if !seen[text] {
				cfg.IPv6Prefixes = append(cfg.IPv6Prefixes, text)
				seen[text] = true
			}
		}
	}
	if len(cfg.IPv6Prefixes) == 0 {
		return fmt.Errorf("局域网尚无 IPv6 /64 前缀，请先在路由器启用 IPv6")
	}
	for _, client := range cfg.clients() {
		ip := net.ParseIP(client).To4()
		if ip == nil {
			return fmt.Errorf("无效的设备 IPv4")
		}
		// A single, interface-bound LAN ping refreshes the normal ARP neighbour entry.
		localTool("/sbin/ping", "-n", "-c", "1", "-W", "800", "-b", cfg.Interface, client)
		text := localTool("/usr/sbin/arp", "-n", client)
		var found net.HardwareAddr
		for _, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, "("+client+")") || !strings.Contains(line, " on "+cfg.Interface+" ") {
				continue
			}
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "at" && i+1 < len(fields) {
					found, _ = parseLANMAC(fields[i+1])
				}
			}
		}
		if !validPeerMAC(found, lan.HardwareAddr) {
			continue // Offline devices do not prevent other selected devices from forwarding.
		}
		seed := peerSeed{IP: client, MAC: found.String()}
		cfg.Peers = append(cfg.Peers, seed)
	}
	// Cached link-local neighbours allow immediate per-device RAs. If missing,
	// wait for that selected device's RS after it reconnects to Wi-Fi.
	text := localTool("/usr/sbin/ndp", "-an")
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil || !addr.IsLinkLocalUnicast() || addr.Zone() != cfg.Interface {
			continue
		}
		m, err := parseLANMAC(f[1])
		if err != nil {
			continue
		}
		for i := range cfg.Peers {
			if cfg.Peers[i].MAC == m.String() {
				cfg.Peers[i].LinkLocal = addr.WithZone("").String()
			}
		}
	}
	return nil
}

func joinIPv6Groups(index int, router netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return -1, err
	}
	group := [16]byte{0xff, 0x02}
	group[11] = 1
	group[12] = 0xff
	r := router.As16()
	copy(group[13:], r[13:])
	for _, addr := range [][16]byte{netip.MustParseAddr("ff02::2").As16(), group} {
		if err = unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &unix.IPv6Mreq{Multiaddr: addr, Interface: uint32(index)}); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}
