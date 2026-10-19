package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func dualConfig() configuration {
	c := testConfig
	c.AdditionalClients = []string{"10.42.0.60"}
	c.IPv6 = true
	c.IPv6Prefixes = []string{"fd42:10:20:30::/64"}
	c.Peers = []peerSeed{{IP: c.Client, MAC: ps5mac.String()}, {IP: c.AdditionalClients[0], MAC: "02:06:04:03:02:01"}}
	return c
}

func TestTwoDevicesDualStackTCPUDP(t *testing.T) {
	twoDevicesDualStack(t, false)
}

func TestAutoDevicesDualStackTCPUDP(t *testing.T) {
	twoDevicesDualStack(t, true)
}

func twoDevicesDualStack(t *testing.T, automatic bool) {
	t.Helper()
	cfg := dualConfig()
	type guest struct {
		stack *stack.Stack
		link  *channel.Endpoint
		mac   net.HardwareAddr
	}
	var guests []guest
	for i, ip := range cfg.clients() {
		s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
		link := channel.New(1024, 1280, "")
		if err := s.CreateNIC(1, link); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{ip, fmt.Sprintf("fd42:10:20:30::%d", 50+i)} {
			a := netip.MustParseAddr(addr)
			proto := ipv4.ProtocolNumber
			bits := 24
			if a.Is6() {
				proto = ipv6.ProtocolNumber
				bits = 64
			}
			if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(a.AsSlice()), PrefixLen: bits}}, stack.AddressProperties{}); err != nil {
				t.Fatal(err)
			}
		}
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
		m, _ := net.ParseMAC(cfg.Peers[i].MAC)
		guests = append(guests, guest{s, link, m})
	}
	engineConfig := cfg
	if automatic {
		engineConfig.AutoDiscover = true
		engineConfig.Client = ""
		engineConfig.AdditionalClients = nil
		engineConfig.Peers = nil
	}
	e, err := newEngine(engineConfig, mac, func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		host := "127.0.0.1"
		if network == "tcp6" || network == "udp6" {
			host = "::1"
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}, func(f []byte) error {
		for _, g := range guests {
			if bytes.Equal(f[:6], g.mac) {
				proto := ipv4.ProtocolNumber
				if binary.BigEndian.Uint16(f[12:]) == 0x86dd {
					proto = ipv6.ProtocolNumber
				}
				p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), f[14:]...))})
				g.link.InjectInbound(proto, p)
				p.DecRef()
				return nil
			}
		}
		return fmt.Errorf("reply sent to an unselected MAC")
	})
	if err != nil {
		t.Fatal(err)
	}
	e.v6Ready.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	var pumps sync.WaitGroup
	for _, g := range guests {
		pumps.Add(1)
		go func(g guest) {
			defer pumps.Done()
			for {
				p := g.link.ReadContext(ctx)
				if p == nil {
					return
				}
				v := p.ToView()
				ip := append([]byte(nil), v.AsSlice()...)
				v.Release()
				p.DecRef()
				f := make([]byte, 14+len(ip))
				copy(f, mac)
				copy(f[6:], g.mac)
				kind := uint16(0x0800)
				if ip[0]>>4 == 6 {
					kind = 0x86dd
				}
				binary.BigEndian.PutUint16(f[12:], kind)
				copy(f[14:], ip)
				e.input(f)
			}
		}(g)
	}
	t.Cleanup(func() {
		cancel()
		e.close()
		for _, g := range guests {
			g.stack.Destroy()
			g.link.Close()
		}
		pumps.Wait()
	})
	var flows sync.WaitGroup
	families := [][]string{{"4", "6"}}
	if automatic {
		families = [][]string{{"4"}, {"6"}}
	}
	for _, group := range families {
		for i, g := range guests {
			for _, family := range group {
				for _, kind := range []string{"tcp", "udp"} {
					flows.Add(1)
					go func(i int, g guest, family, kind string) {
						defer flows.Done()
						network := kind + family
						listen := "127.0.0.1:0"
						target := "198.51.100.8"
						proto := ipv4.ProtocolNumber
						if family == "6" {
							listen = "[::1]:0"
							target = "2001:db8::8"
							proto = ipv6.ProtocolNumber
						}
						var port uint16
						if kind == "tcp" {
							ln, err := net.Listen(network, listen)
							if err != nil {
								t.Error(err)
								return
							}
							defer ln.Close()
							port = uint16(ln.Addr().(*net.TCPAddr).Port)
							go func() {
								c, err := ln.Accept()
								if err == nil {
									defer c.Close()
									io.Copy(c, c)
								}
							}()
						} else {
							pc, err := net.ListenPacket(network, listen)
							if err != nil {
								t.Error(err)
								return
							}
							defer pc.Close()
							port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
							go func() {
								b := make([]byte, 16000)
								for {
									n, a, err := pc.ReadFrom(b)
									if err != nil {
										return
									}
									pc.WriteTo(b[:n], a)
								}
							}()
						}
						addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(target).AsSlice()), Port: port}
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						var conn net.Conn
						var err error
						if kind == "tcp" {
							conn, err = gonet.DialContextTCP(ctx, g.stack, addr, proto)
						} else {
							conn, err = gonet.DialUDP(g.stack, nil, &addr, proto)
						}
						if err != nil {
							t.Errorf("device %d %s: %v", i, network, err)
							return
						}
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						payload := bytes.Repeat([]byte(fmt.Sprintf("device%d-%s/", i, network)), 600)
						if _, err = conn.Write(payload); err != nil {
							t.Errorf("device %d %s write: %v", i, network, err)
							return
						}
						b := make([]byte, len(payload))
						if _, err = io.ReadFull(conn, b); err != nil || !bytes.Equal(b, payload) {
							t.Errorf("device %d %s incorrect reply: %v", i, network, err)
						}
					}(i, g, family, kind)
				}
			}
		}
		flows.Wait()
	}
	if len(e.deviceReports()) != 2 {
		t.Fatal("two devices were not independently admitted")
	}
	if e.stats.IPv6Packets.Load() == 0 || e.stats.IPv6Replies.Load() == 0 {
		t.Fatal("IPv6 did not really flow")
	}
	for _, d := range e.deviceReports() {
		if d.UploadBytes == 0 || d.DownloadBytes == 0 || d.IPv6Packets == 0 {
			t.Fatalf("device not independently counted: %+v", d)
		}
	}
}

func TestSelectedIPv6FilterAndScope(t *testing.T) {
	cfg := dualConfig()
	raw := captureFilters(cfg, mac)
	p := make([]bpf.RawInstruction, len(raw))
	for i, r := range raw {
		p[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	ins, ok := bpf.Disassemble(p)
	if !ok {
		t.Fatal("invalid filter")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	f := make([]byte, 62)
	copy(f, mac)
	copy(f[6:], ps5mac)
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	f[14] = 0x60
	if n, _ := vm.Run(f); n == 0 {
		t.Fatal("selected IPv6 not captured")
	}
	f[6] = 4
	if n, _ := vm.Run(f); n != 0 {
		t.Fatal("other device IPv6 captured")
	}
	f[6] = 2
	cfg.IPv6 = false
	off := captureFilters(cfg, mac)
	op := make([]bpf.RawInstruction, len(off))
	for i, r := range off {
		op[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	oi, ok := bpf.Disassemble(op)
	if !ok {
		t.Fatal("invalid IPv4-only filter")
	}
	ov, err := bpf.NewVM(oi)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := ov.Run(f); n != 0 {
		t.Fatal("IPv6 captured while disabled")
	}

	e, err := newEngine(dualConfig(), mac, localDial, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	e.v6Ready.Store(true)
	makeFrame := func(src, dst string) []byte {
		ip := make([]byte, 48)
		ip[0] = 0x60
		ip[6] = 17
		binary.BigEndian.PutUint16(ip[4:], 8)
		copy(ip[8:], netip.MustParseAddr(src).AsSlice())
		copy(ip[24:], netip.MustParseAddr(dst).AsSlice())
		f := append(make([]byte, 14), ip...)
		copy(f, mac)
		copy(f[6:], ps5mac)
		binary.BigEndian.PutUint16(f[12:], 0x86dd)
		return f
	}
	for _, pair := range [][2]string{{"fd42:10:20:30::50", "fd42:10:20:30::1"}, {"fd42:10:20:30::50", "::1"}, {"2001:db8:999::50", "2001:db8::8"}} {
		if e.input(makeFrame(pair[0], pair[1])) {
			t.Fatal("out of scope IPv6 accepted")
		}
	}
}

func TestIPv6RouterAdvertisementAndWithdrawal(t *testing.T) {
	cfg := dualConfig()
	cfg.Peers[0].LinkLocal = "fe80::50"
	var mu sync.Mutex
	var frames [][]byte
	e, err := newEngine(cfg, mac, localDial, func(f []byte) error {
		mu.Lock()
		frames = append(frames, append([]byte(nil), f...))
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.v6Ready.Store(true)
	e.advertiseIPv6(false)
	e.close()
	if len(frames) != 2 {
		t.Fatalf("wanted RA and withdrawal, got %d", len(frames))
	}
	for i, f := range frames {
		ip := f[14:]
		src := netip.AddrFrom16([16]byte(ip[8:24]))
		dst := netip.AddrFrom16([16]byte(ip[24:40]))
		b := ip[40:]
		if !bytes.Equal(f[:6], ps5mac) || dst.String() != "fe80::50" || !src.IsLinkLocalUnicast() || ip[7] != 255 || b[0] != 134 || icmp6Checksum(src, dst, b) != 0 {
			t.Fatal("invalid or non-unicast RA")
		}
		life := binary.BigEndian.Uint16(b[6:])
		if i == 0 && life != routerLifetime || i == 1 && life != 0 {
			t.Fatal("incorrect router lifetime")
		}
	}
}

func TestIPv6NDScopeAndChecksum(t *testing.T) {
	e, err := newEngine(dualConfig(), mac, localDial, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	src := netip.MustParseAddr("fe80::50")
	dst := netip.MustParseAddr("ff02::2")
	body := make([]byte, 8)
	body[0] = 133
	ip := make([]byte, 48)
	ip[0] = 0x60
	ip[6] = 58
	ip[7] = 255
	binary.BigEndian.PutUint16(ip[4:], 8)
	copy(ip[8:], src.AsSlice())
	copy(ip[24:], dst.AsSlice())
	copy(ip[40:], body)
	binary.BigEndian.PutUint16(ip[42:], icmp6Checksum(src, dst, body))
	f := append(make([]byte, 14), ip...)
	copy(f, []byte{0x33, 0x33, 0, 0, 0, 2})
	copy(f[6:], ps5mac)
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	if !e.input(f) {
		t.Fatal("valid selected router solicitation rejected")
	}
	f[6] ^= 8
	if e.input(f) {
		t.Fatal("foreign device RS accepted")
	}
	f[6] ^= 8
	f[21] = 64
	if e.input(f) {
		t.Fatal("off-link RS accepted")
	}
	f[21] = 255
	f[56] ^= 1
	if e.input(f) {
		t.Fatal("corrupt RS accepted")
	}
}

func TestIPv6BindingAndProbeNeverFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, network := range []string{"tcp6", "udp6"} {
		c, err := vpnDialer(0x7fffffff)(ctx, network, "[::1]:9")
		if c != nil {
			c.Close()
		}
		if err == nil {
			t.Fatal("IPv6 binding allowed nonexistent interface")
		}
	}
	called := false
	err := probeIPv6(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		called = true
		if network != "tcp6" {
			t.Error("IPv6 probe fell back")
		}
		h, _, _ := net.SplitHostPort(address)
		if a, err := netip.ParseAddr(h); err != nil || !a.Is6() {
			t.Error("probe target was not IPv6")
		}
		return nil, syscall.ENETUNREACH
	})
	if err == nil || !called {
		t.Fatal("failed IPv6 exit reported ready")
	}
}

func TestIPv6DuplicateRouterDetection(t *testing.T) {
	var sent int
	e, err := newEngine(dualConfig(), mac, localDial, func([]byte) error { sent++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	f := e.duplicateAddressProbe()
	ip := f[14:]
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	if !src.IsUnspecified() || !dst.IsMulticast() || ip[7] != 255 || icmp6Checksum(src, dst, ip[40:]) != 0 || len(ip) != 64 {
		t.Fatal("invalid DAD solicitation")
	}
	na := make([]byte, 32)
	na[0] = 136
	copy(na[8:], e.v6Router.AsSlice())
	reply := e.controlFrame(mac, netip.MustParseAddr("ff02::1"), na)
	copy(reply[6:], []byte{2, 9, 9, 9, 9, 9})
	e.v6DAD.Store(true)
	if !e.input(reply) || !e.v6Conflict.Load() {
		t.Fatal("duplicate virtual router was not detected")
	}
	e.v6Ready.Store(true)
	e.advertiseIPv6(false)
	if sent != 0 {
		t.Fatal("advertised a conflicting IPv6 router")
	}
	cfg := dualConfig()
	cfg.Router = e.v6Router
	raw := captureFilters(cfg, mac)
	p := make([]bpf.RawInstruction, len(raw))
	for i, r := range raw {
		p[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	ins, ok := bpf.Disassemble(p)
	if !ok {
		t.Fatal("invalid DAD filter")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := vm.Run(reply); n == 0 {
		t.Fatal("DAD collision not captured")
	}
	reply[77] ^= 1
	if n, _ := vm.Run(reply); n != 0 {
		t.Fatal("unrelated neighbour advertisement captured")
	}
}

func TestDeviceIdentityAndPrivacyAddressBounds(t *testing.T) {
	e, err := newEngine(dualConfig(), mac, localDial, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	if p := e.acceptPeer(netip.MustParseAddr(testConfig.Client), net.HardwareAddr{2, 6, 4, 3, 2, 1}); p != nil {
		t.Fatal("second device stole first IPv4 identity")
	}
	for i := 1; i <= 100; i++ {
		if e.acceptPeer(netip.MustParseAddr(fmt.Sprintf("fd42:10:20:30::%x", i)), ps5mac) == nil {
			t.Fatal("selected privacy address rejected")
		}
	}
	if len(e.addresses) > 34 {
		t.Fatal("privacy-address map unbounded")
	}
	m, err := parseLANMAC("2:5:4:3:2:1")
	if err != nil || !bytes.Equal(m, ps5mac) {
		t.Fatal("Darwin ARP abbreviated MAC not accepted")
	}
	for _, bad := range []string{"2:5:4:3:2", "2:5:4:3:2:xyz", "222:5:4:3:2:1"} {
		if _, err := parseLANMAC(bad); err == nil {
			t.Fatal("invalid neighbour MAC accepted")
		}
	}
}

func TestDNSAAAAAndIPv6EndpointAssociation(t *testing.T) {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("game.example.test."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{q}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("2001:db8::8")
	reply, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 17, Response: true}, Questions: []dnsmessage.Question{q}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	var cache nameCache
	observer := dnsObserver{cache: &cache}
	observer.query(query)
	observer.reply(reply)
	if names := cache.lookup(ip.String(), time.Now()); len(names) != 1 || names[0] != "game.example.test" {
		t.Fatal("IPv6 domain association absent")
	}
	var r endpointRegistry
	r.beginFrom("TCP", "[2001:db8::8]:443", "10.42.0.50")
	r.beginFrom("TCP", "[2001:db8::8]:443", "10.42.0.60")
	if rows := r.snapshot(); len(rows) != 2 || rows[0].Client == rows[1].Client {
		t.Fatal("two devices' IPv6 destinations merged")
	}
}
