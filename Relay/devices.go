package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

type peerSeed struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	LinkLocal string `json:"linkLocal,omitempty"`
}

type devicePeer struct {
	ip          netip.Addr
	mac         net.HardwareAddr
	linkLocal   netip.Addr
	addresses   []netip.Addr
	v4addresses []netip.Addr
	upload      atomic.Uint64
	download    atomic.Uint64
	last        atomic.Int64
	v6packets   atomic.Uint64
	lastRA      time.Time
}

type deviceReport struct {
	IP            string  `json:"ip"`
	MAC           string  `json:"mac,omitempty"`
	LinkLocal     string  `json:"linkLocal,omitempty"`
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBytes uint64  `json:"downloadBytes"`
	LastAt        float64 `json:"lastAt"`
	IPv6Packets   uint64  `json:"ipv6Packets"`
}

const maxAutoDevices = 32

func (c configuration) clients() []string {
	if c.AutoDiscover {
		return nil
	}
	return append([]string{c.Client}, c.AdditionalClients...)
}

func validLANClient(ip, gateway netip.Addr, subnet netip.Prefix) bool {
	if !ip.Is4() || !ip.IsPrivate() || !subnet.Contains(ip) || ip == gateway || ip == subnet.Addr() {
		return false
	}
	host := ^uint32(0) >> subnet.Bits()
	return binary.BigEndian.Uint32(ip.AsSlice())&host != host
}

// Check the IPv4 header before an unknown source can occupy an admission slot.
// Transport validation remains in Netstack, including fragment reassembly.
func validIPv4Packet(ip []byte) bool {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return false
	}
	n := int(ip[0]&15) * 4
	if n < 20 || n > len(ip) {
		return false
	}
	var sum uint32
	for i := 0; i < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return sum == 65535
}

func (e *engine) initDevices() error {
	e.devices = make(map[netip.Addr]*devicePeer)
	e.addresses = make(map[netip.Addr]*devicePeer)
	e.byMAC = make(map[string]*devicePeer)
	if len(e.config.clients()) > 8 {
		return fmt.Errorf("最多同时转发 8 台设备")
	}
	for _, text := range e.config.clients() {
		ip, err := netip.ParseAddr(text)
		if err != nil || !ip.Is4() || !e.subnet.Contains(ip) || ip == e.clientGateway || ip == e.subnet.Addr() {
			return fmt.Errorf("设备 IPv4 必须是所选局域网中的有效主机地址")
		}
		if binary.BigEndian.Uint32(ip.AsSlice())&(^uint32(0)>>e.subnet.Bits()) == (^uint32(0) >> e.subnet.Bits()) {
			return fmt.Errorf("设备 IP 不能是广播地址")
		}
		if e.devices[ip] != nil {
			return fmt.Errorf("设备 IP 不能重复")
		}
		p := &devicePeer{ip: ip}
		for _, seed := range e.config.Peers {
			if seed.IP != text {
				continue
			}
			mac, err := net.ParseMAC(seed.MAC)
			if err != nil || !validPeerMAC(mac, e.mac) || e.byMAC[string(mac)] != nil {
				return fmt.Errorf("设备 Wi-Fi 地址无效或重复")
			}
			p.mac = append(net.HardwareAddr(nil), mac...)
			ll, _ := netip.ParseAddr(seed.LinkLocal)
			if ll.Is6() && ll.IsLinkLocalUnicast() {
				p.linkLocal = ll.WithZone("")
			}
			e.byMAC[string(p.mac)] = p
		}
		e.devices[ip], e.addresses[ip] = p, p
	}
	return nil
}

func validPeerMAC(mac, own net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 && !bytes.Equal(mac, own) && !bytes.Equal(mac, make([]byte, 6))
}

// All peer and address maps are protected by peerMu. IPv6 privacy addresses
// are learned only from the already-selected device MAC, within the LAN prefix.
func (e *engine) acceptPeer(src netip.Addr, mac net.HardwareAddr) *devicePeer {
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	if !validPeerMAC(mac, e.mac) {
		return nil
	}
	if src.Is4() {
		p := e.devices[src]
		if e.config.AutoDiscover {
			if !validLANClient(src, e.clientGateway, e.subnet) || src == e.config.LANRouter {
				return nil
			}
			p = e.addresses[src]
			if p == nil {
				p = e.byMAC[string(mac)]
				if p == nil {
					if len(e.devices) >= maxAutoDevices {
						return nil
					}
					p = &devicePeer{ip: src, mac: append(net.HardwareAddr(nil), mac...)}
					e.byMAC[string(mac)] = p
				} else {
					delete(e.devices, p.ip)
				}
				p.ip = src
				p.v4addresses = append(p.v4addresses, src)
				if len(p.v4addresses) > 8 {
					delete(e.addresses, p.v4addresses[0])
					p.v4addresses = p.v4addresses[1:]
				}
				e.devices[src], e.addresses[src] = p, p
			}
		}
		if p == nil {
			return nil
		}
		if p.mac == nil {
			if e.byMAC[string(mac)] != nil {
				return nil
			}
			p.mac = append(net.HardwareAddr(nil), mac...)
			e.byMAC[string(mac)] = p
		}
		if !bytes.Equal(p.mac, mac) {
			return nil
		}
		return p
	}
	p := e.byMAC[string(mac)]
	if p == nil || !src.Is6() || !src.IsGlobalUnicast() || !e.onIPv6LAN(src) {
		return nil
	}
	if other := e.addresses[src]; other != nil && other != p {
		return nil
	}
	if e.addresses[src] == nil {
		if len(p.addresses) >= 32 {
			delete(e.addresses, p.addresses[0])
			p.addresses = p.addresses[1:]
		}
		p.addresses = append(p.addresses, src)
		e.addresses[src] = p
	}
	return p
}

func (e *engine) onIPv6LAN(addr netip.Addr) bool {
	for _, prefix := range e.v6Prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (e *engine) deviceReports() []deviceReport {
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	var rows []deviceReport
	clients := e.config.clients()
	if e.config.AutoDiscover {
		for ip := range e.devices {
			clients = append(clients, ip.String())
		}
		sort.Slice(clients, func(i, j int) bool { return netip.MustParseAddr(clients[i]).Less(netip.MustParseAddr(clients[j])) })
	}
	for _, text := range clients {
		p := e.devices[netip.MustParseAddr(text)]
		row := deviceReport{IP: text, UploadBytes: p.upload.Load(), DownloadBytes: p.download.Load(), LastAt: float64(p.last.Load()) / 1000, IPv6Packets: p.v6packets.Load()}
		if p.mac != nil {
			row.MAC = p.mac.String()
		}
		if p.linkLocal.IsValid() {
			row.LinkLocal = p.linkLocal.String()
		}
		rows = append(rows, row)
	}
	return rows
}
