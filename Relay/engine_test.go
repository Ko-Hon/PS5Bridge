package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/bpf"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var testConfig = configuration{Interface: "en0", Gateway: "10.42.0.10", Mask: "255.255.255.0", Client: "10.42.0.50"}
var mac = net.HardwareAddr{2, 1, 2, 3, 4, 5}
var ps5mac = net.HardwareAddr{2, 5, 4, 3, 2, 1}

func ether(ip []byte) []byte {
	f := make([]byte, 14+len(ip))
	copy(f, mac)
	copy(f[6:], ps5mac)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	copy(f[14:], ip)
	return f
}

func console(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) (*engine, *stack.Stack) {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(1024, 1500, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.AddrFromSlice(net.ParseIP(testConfig.Client).To4())
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	e, err := newEngine(testConfig, mac, dial, func(frame []byte) error {
		if !bytes.Equal(frame[:6], ps5mac) || !bytes.Equal(frame[6:12], mac) {
			return fmt.Errorf("incorrect reply MAC")
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), frame[14:]...))})
		link.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			p := link.ReadContext(ctx)
			if p == nil {
				return
			}
			v := p.ToView()
			frame := ether(v.AsSlice())
			v.Release()
			p.DecRef()
			e.input(frame)
		}
	}()
	t.Cleanup(func() { cancel(); e.close(); s.Destroy(); link.Close(); <-done })
	return e, s
}

func localDial(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}
func destination(port int) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(net.IPv4(198, 51, 100, 8).To4()), Port: uint16(port)}
}

func TestTCPEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	e, s := console(t, localDial)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, destination(ln.Addr().(*net.TCPAddr).Port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("PS5-stream-"), 10000)
	go func() { c.Write(payload); c.CloseWrite() }()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("TCP mismatch: %d/%d", len(got), len(payload))
	}
	if e.stats.TCP.Load() != 1 || e.stats.Packets.Load() == 0 || e.stats.Replies.Load() == 0 {
		t.Fatal("no real TCP packet exchange")
	}
	rows := e.endpoints.snapshot()
	if len(rows) != 1 || rows[0].Protocol != "TCP" || rows[0].IP != "198.51.100.8" || int(rows[0].Port) != ln.Addr().(*net.TCPAddr).Port || rows[0].ConnectLatency == nil {
		t.Fatalf("TCP telemetry did not preserve the console's actual destination: %+v", rows)
	}
	e.close()
	if e.stats.UploadBytes.Load() < uint64(len(payload)) || e.stats.DownloadBytes.Load() < uint64(len(payload)) || e.stats.LastClientAt.Load() == 0 {
		t.Fatal("TCP traffic was not metered in both directions")
	}
}

func TestUDPEndToEndAndFragmentation(t *testing.T) {
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := host.ReadFromUDP(b)
			if err != nil {
				return
			}
			host.WriteToUDP(b[:n], a)
		}
	}()
	e, s := console(t, localDial)
	dest := destination(host.LocalAddr().(*net.UDPAddr).Port)
	for flow := 0; flow < 3; flow++ {
		c, err := gonet.DialUDP(s, nil, &dest, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{0, 64, 1200, 8192} {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{byte(flow + 1)}, size)
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 10000)
			n, err := c.Read(got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:n], payload) {
				t.Fatalf("UDP datagram mismatch size=%d got=%d", size, n)
			}
		}
		c.Close()
	}
	if e.stats.UDP.Load() != 3 {
		t.Fatalf("UDP flows=%d", e.stats.UDP.Load())
	}
	rows := e.endpoints.snapshot()
	if len(rows) != 1 || rows[0].Protocol != "UDP" || rows[0].IP != "198.51.100.8" || int(rows[0].Port) != host.LocalAddr().(*net.UDPAddr).Port || rows[0].ConnectLatency != nil {
		t.Fatalf("UDP telemetry must preserve target and never invent RTT: %+v", rows)
	}
	e.close()
	if e.stats.UploadBytes.Load() < 28368 || e.stats.DownloadBytes.Load() < 28368 {
		t.Fatal("fragmented UDP traffic not metered")
	}
}

func TestDialFailureDoesNotReportTCPConnected(t *testing.T) {
	e, s := console(t, func(context.Context, string, string) (net.Conn, error) { return nil, fmt.Errorf("VPN unavailable") })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, destination(443), ipv4.ProtocolNumber)
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("failed VPN must not accept TCP")
	}
	if e.stats.Failures.Load() == 0 {
		t.Fatal("failure not recorded")
	}
}

func TestFrameScope(t *testing.T) {
	e, err := newEngine(testConfig, mac, localDial, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	ip := make([]byte, 28)
	ip[0] = 0x45
	ip[9] = 17
	binary.BigEndian.PutUint16(ip[2:], 28)
	copy(ip[12:], net.ParseIP(testConfig.Client).To4())
	copy(ip[16:], net.IPv4(1, 1, 1, 1).To4())
	base := ether(ip)
	for name, mutate := range map[string]func([]byte){
		"other console": func(f []byte) { f[29]++ }, "other destination MAC": func(f []byte) { f[0]++ }, "loopback": func(f []byte) { copy(f[30:], net.IPv4(127, 0, 0, 1).To4()) }, "LAN": func(f []byte) { copy(f[30:], net.IPv4(10, 42, 0, 1).To4()) }, "multicast MAC": func(f []byte) { f[6] = 1 }, "IPv6": func(f []byte) { f[12] = 0x86; f[13] = 0xdd }, "oversized IP": func(f []byte) { binary.BigEndian.PutUint16(f[16:], 65535) },
	} {
		t.Run(name, func(t *testing.T) {
			f := append([]byte(nil), base...)
			mutate(f)
			if e.input(f) {
				t.Fatal("out-of-scope frame accepted")
			}
		})
	}
	for i := 0; i < 34; i++ {
		if e.input(base[:i]) {
			t.Fatal("truncated frame accepted")
		}
	}
	if e.stats.Packets.Load() != 0 {
		t.Fatal("unrelated traffic captured")
	}
	if e.stats.UploadBytes.Load() != 0 || e.stats.DownloadBytes.Load() != 0 || e.stats.LastClientAt.Load() != 0 {
		t.Fatal("unrelated traffic changed selected-console statistics")
	}
}

func record(frame []byte) []byte {
	b := make([]byte, (20+len(frame)+3)&^3)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(frame)))
	binary.LittleEndian.PutUint16(b[16:], 20)
	copy(b[20:], frame)
	return b
}
func TestBPFRecords(t *testing.T) {
	frames := [][]byte{make([]byte, 42), make([]byte, 1514)}
	var data []byte
	for _, f := range frames {
		data = append(data, record(f)...)
	}
	count := 0
	if err := bpfRecords(data, func([]byte) { count++ }); err != nil || count != 2 {
		t.Fatalf("valid records count=%d err=%v", count, err)
	}
	for _, offset := range []int{8, 12, 16} {
		b := append([]byte(nil), data...)
		for i := 0; i < 4 && offset+i < len(b); i++ {
			b[offset+i] = 255
		}
		if bpfRecords(b, func([]byte) {}) == nil {
			t.Fatalf("invalid length accepted at %d", offset)
		}
	}
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 10000; i++ {
		b := make([]byte, r.Intn(512))
		r.Read(b)
		bpfRecords(b, func([]byte) {})
	}
}

func TestMissingVPNBindingFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := vpnDialer(0x7fffffff)(ctx, "tcp4", "127.0.0.1:9")
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("nonexistent VPN interface allowed a connection")
	}
}

func TestKernelCaptureFilterScope(t *testing.T) {
	raw := captureFilter(net.ParseIP(testConfig.Client), mac)
	program := make([]bpf.RawInstruction, len(raw))
	for i, r := range raw {
		program[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	instructions, ok := bpf.Disassemble(program)
	if !ok {
		t.Fatal("invalid BPF program")
	}
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	copy(ip[12:], net.ParseIP(testConfig.Client).To4())
	frame := ether(ip)
	if n, err := vm.Run(frame); err != nil || n == 0 {
		t.Fatalf("selected console was not captured: %d %v", n, err)
	}
	for _, offset := range []int{0, 4, 12, 26, 29} {
		wrong := append([]byte(nil), frame...)
		wrong[offset] ^= 1
		if n, _ := vm.Run(wrong); n != 0 {
			t.Fatalf("unrelated frame captured after mutation at %d", offset)
		}
	}
}

func TestStopClosesActiveFlow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			server <- c
		}
	}()
	e, s := console(t, localDial)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	guest, err := gonet.DialContextTCP(ctx, s, destination(listener.Addr().(*net.TCPAddr).Port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	host := <-server
	defer host.Close()
	e.close()
	host.SetReadDeadline(time.Now().Add(time.Second))
	_, err = host.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("upstream connection survived stop")
	}
}
