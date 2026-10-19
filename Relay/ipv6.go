package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const routerLifetime = 45

func (e *engine) duplicateAddressProbe() []byte {
	a := e.v6Router.As16()
	group := [16]byte{0xff, 0x02}
	group[11] = 1
	group[12] = 0xff
	copy(group[13:], a[13:])
	dst := netip.AddrFrom16(group)
	mac := net.HardwareAddr{0x33, 0x33, 0xff, a[13], a[14], a[15]}
	b := make([]byte, 24)
	b[0] = 135
	copy(b[8:], a[:])
	f := e.controlFrame(mac, dst, b)
	clear(f[22:38])
	f[56], f[57] = 0, 0
	binary.BigEndian.PutUint16(f[56:], icmp6Checksum(netip.IPv6Unspecified(), dst, f[54:]))
	return f
}

// The sole exception to selected-source capture is DAD for our fresh random
// virtual address. It cannot forward data or alter another device's routing.
func (e *engine) observeDAD(frame, ip []byte) bool {
	if !e.v6DAD.Load() || len(ip) < 64 || ip[7] != 255 || ip[6] != 58 || string(frame[6:12]) == string(e.mac) {
		return false
	}
	b := ip[40:]
	if b[1] != 0 || (b[0] != 135 && b[0] != 136) || netip.AddrFrom16([16]byte(b[8:24])) != e.v6Router {
		return false
	}
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	if icmp6Checksum(src, dst, b) != 0 {
		return false
	}
	e.v6Conflict.Store(true)
	return true
}

func (e *engine) initIPv6() error {
	if !e.config.IPv6 {
		return nil
	}
	for _, text := range e.config.IPv6Prefixes {
		p, err := netip.ParsePrefix(text)
		if err != nil || !p.Addr().Is6() || !p.Addr().IsGlobalUnicast() || p.Bits() != 64 {
			return fmt.Errorf("IPv6 需要局域网现有的 /64 前缀")
		}
		e.v6Prefixes = append(e.v6Prefixes, p.Masked())
	}
	if len(e.v6Prefixes) == 0 {
		return fmt.Errorf("当前局域网没有可用于设备的 IPv6 /64 前缀，请先在路由器上启用 IPv6")
	}
	// A distinct, random link-local router avoids the host kernel's non-router
	// neighbour advertisements. This address is never assigned to the system.
	b := [16]byte{0xfe, 0x80}
	if _, err := rand.Read(b[8:]); err != nil {
		return err
	}
	e.v6Router = netip.AddrFrom16(b)
	return nil
}

func icmp6Checksum(src, dst netip.Addr, payload []byte) uint16 {
	var sum uint32
	for _, b := range [][]byte{src.AsSlice(), dst.AsSlice()} {
		for i := 0; i < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	sum += uint32(len(payload)>>16) + uint32(len(payload)&65535) + 58
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i:]))
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (e *engine) controlFrame(peer net.HardwareAddr, dst netip.Addr, body []byte) []byte {
	f := make([]byte, 14+40+len(body))
	copy(f, peer)
	copy(f[6:], e.mac)
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	ip := f[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(body)))
	ip[6] = 58
	ip[7] = 255
	copy(ip[8:], e.v6Router.AsSlice())
	copy(ip[24:], dst.AsSlice())
	copy(ip[40:], body)
	binary.BigEndian.PutUint16(ip[42:], icmp6Checksum(e.v6Router, dst, ip[40:]))
	return f
}

func (e *engine) routerAdvertisement(p *devicePeer, lifetime uint16) []byte {
	b := make([]byte, 32+32*len(e.v6Prefixes))
	b[0] = 134
	b[4] = 64
	b[5] = 0x08 // High default-router preference; no DHCP changes.
	binary.BigEndian.PutUint16(b[6:], lifetime)
	b[16] = 1
	b[17] = 1
	copy(b[18:24], e.mac)
	b[24] = 5
	b[25] = 1
	binary.BigEndian.PutUint32(b[28:], 1280)
	for i, prefix := range e.v6Prefixes {
		o := 32 + i*32
		b[o] = 3
		b[o+1] = 4
		b[o+2] = 64
		b[o+3] = 0xc0
		// Re-advertise only an existing LAN prefix, never a new global subnet.
		binary.BigEndian.PutUint32(b[o+4:], 180)
		binary.BigEndian.PutUint32(b[o+8:], 90)
		copy(b[o+16:], prefix.Addr().AsSlice())
	}
	return e.controlFrame(p.mac, p.linkLocal, b)
}

// Every RA is IPv6-unicast AND Ethernet-unicast to a selected device. No
// network-wide default-router announcement, prefix takeover or DNS change.
func (e *engine) advertiseIPv6(withdraw bool) {
	if !e.config.IPv6 || !withdraw && (!e.v6Ready.Load() || e.v6Conflict.Load()) {
		return
	}
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	for _, p := range e.devices {
		if p.mac == nil || !p.linkLocal.IsValid() {
			continue
		}
		if withdraw && p.lastRA.IsZero() {
			continue
		}
		if !withdraw && time.Since(p.lastRA) < 10*time.Second {
			continue
		}
		lifetime := uint16(routerLifetime)
		if withdraw {
			lifetime = 0
		}
		if e.send(e.routerAdvertisement(p, lifetime)) == nil {
			if withdraw {
				p.lastRA = time.Time{}
			} else {
				p.lastRA = time.Now()
			}
		}
	}
}

// Only valid hop-limit-255, checksum-verified ND from a selected MAC enters.
func (e *engine) ipv6Control(frame, ip []byte) bool {
	if !e.config.IPv6 || len(ip) < 48 || ip[6] != 58 || ip[7] != 255 {
		return false
	}
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	b := ip[40:]
	if b[1] != 0 || icmp6Checksum(src, dst, b) != 0 {
		return false
	}
	e.peerMu.Lock()
	p := e.byMAC[string(frame[6:12])]
	if p == nil || !src.IsLinkLocalUnicast() {
		e.peerMu.Unlock()
		return false
	}
	// Router solicitations and NS are the only control inputs accepted here.
	if b[0] != 133 && b[0] != 135 {
		e.peerMu.Unlock()
		return false
	}
	if b[0] == 133 && (len(b) < 8 || dst != netip.MustParseAddr("ff02::2") && dst != e.v6Router) {
		e.peerMu.Unlock()
		return false
	}
	if b[0] == 135 && (len(b) < 24 || netip.AddrFrom16([16]byte(b[8:24])) != e.v6Router) {
		e.peerMu.Unlock()
		return false
	}
	// Source-LL options, when present, must match the selected Ethernet source.
	start := 8
	if b[0] == 135 {
		start = 24
	}
	for o := start; o < len(b); {
		if o+2 > len(b) || b[o+1] == 0 || o+int(b[o+1])*8 > len(b) {
			e.peerMu.Unlock()
			return false
		}
		if b[o] == 1 && (b[o+1] != 1 || string(b[o+2:o+8]) != string(p.mac)) {
			e.peerMu.Unlock()
			return false
		}
		o += int(b[o+1]) * 8
	}
	p.linkLocal = src
	if b[0] == 135 {
		na := make([]byte, 32)
		na[0] = 136
		na[4] = 0xe0
		copy(na[8:], e.v6Router.AsSlice())
		na[24] = 2
		na[25] = 1
		copy(na[26:], e.mac)
		e.send(e.controlFrame(p.mac, src, na))
	}
	e.peerMu.Unlock()
	if e.v6Ready.Load() {
		e.advertiseIPv6(false)
	}
	return true
}

func (e *engine) ipv6Status() string {
	if !e.config.IPv6 {
		return "未开启"
	}
	if e.v6Conflict.Load() {
		return "IPv6 网关地址冲突，请重新开始；IPv4 继续运行"
	}
	if !e.v6Ready.Load() {
		e.v6Mu.Lock()
		message := e.v6Error
		e.v6Mu.Unlock()
		if message != "" {
			return "IPv6 出口不可用，未发布网关：" + message
		}
		return "IPv6 出口检测中，尚未发布设备网关"
	}
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	ready := 0
	for _, p := range e.devices {
		if !p.lastRA.IsZero() {
			ready++
		}
	}
	return fmt.Sprintf("出口已验证 · %d/%d 台已提供 IPv6 网关 · IPv6 包 %d", ready, len(e.devices), e.stats.IPv6Packets.Load())
}

func probeIPv6(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	tests := []struct{ url, name string }{
		{"https://[2606:4700:4700::1111]/cdn-cgi/trace", "one.one.one.one"},
		{"https://[2001:4860:4860::8888]/resolve?name=example.com&type=AAAA", "dns.google"},
	}
	var last error
	for _, test := range tests {
		tr := &http.Transport{Proxy: nil, DialContext: func(c context.Context, _, address string) (net.Conn, error) { return dial(c, "tcp6", address) }, TLSClientConfig: &tls.Config{ServerName: test.name, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
		req, err := http.NewRequestWithContext(ctx, "GET", test.url, nil)
		if err != nil {
			return err
		}
		req.Host = test.name
		client := &http.Client{Transport: tr, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			tr.CloseIdleConnections()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		tr.CloseIdleConnections()
		if err != nil || resp.StatusCode != 200 {
			last = fmt.Errorf("IPv6 HTTPS 检测失败")
			continue
		}
		if test.name == "dns.google" {
			var result struct {
				Status *int              `json:"Status"`
				Answer []json.RawMessage `json:"Answer"`
			}
			if json.Unmarshal(b, &result) == nil && result.Status != nil && *result.Status == 0 && len(result.Answer) > 0 {
				return nil
			}
		} else {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "ip=") {
					ip, err := netip.ParseAddr(strings.TrimPrefix(line, "ip="))
					if err == nil && ip.Is6() && !ip.Is4In6() {
						return nil
					}
				}
			}
		}
		last = fmt.Errorf("出口未证明 IPv6 连通")
	}
	return last
}

func (e *engine) runIPv6() {
	defer close(e.v6Done)
	e.v6DAD.Store(true)
	if err := e.send(e.duplicateAddressProbe()); err != nil {
		e.v6Mu.Lock()
		e.v6Error = err.Error()
		e.v6Mu.Unlock()
		return
	}
	select {
	case <-e.ctx.Done():
		return
	case <-time.After(time.Second):
	}
	e.v6DAD.Store(false)
	if e.v6Conflict.Load() {
		return
	}
	for e.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(e.ctx, 6*time.Second)
		err := probeIPv6(ctx, e.dial)
		cancel()
		e.v6Mu.Lock()
		e.v6Error = ""
		if err != nil {
			e.v6Error = err.Error()
		}
		e.v6Mu.Unlock()
		if err != nil {
			e.v6Ready.Store(false)
			e.advertiseIPv6(true)
		} else {
			e.v6Ready.Store(true)
			e.advertiseIPv6(false)
		}
		for i := 0; i < 15; i++ {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(time.Second):
				if e.v6Ready.Load() {
					e.advertiseIPv6(false)
				}
			}
		}
	}
}
