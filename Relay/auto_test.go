package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func autoConfig() configuration {
	c := testConfig
	c.Client = ""
	c.AutoDiscover = true
	c.LANRouter = netip.MustParseAddr("10.42.0.1")
	return c
}

func autoFrame(src, dst string, m net.HardwareAddr) []byte {
	f := make([]byte, 42)
	copy(f, mac)
	copy(f[6:], m)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], net.ParseIP(src).To4())
	copy(ip[16:], net.ParseIP(dst).To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(ip[20:], 43000)
	binary.BigEndian.PutUint16(ip[22:], 53000)
	binary.BigEndian.PutUint16(ip[24:], 8)
	return f
}

func TestAutomaticAdmissionScopeAndAddressChanges(t *testing.T) {
	e, err := newEngine(autoConfig(), mac, func(context.Context, string, string) (net.Conn, error) { return nil, fmt.Errorf("test does not dial") }, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	for _, src := range []string{"10.42.0.0", "10.42.0.255", "10.42.0.10", "10.42.0.1", "10.42.1.50", "127.0.0.1", "8.8.8.8"} {
		if e.input(autoFrame(src, "198.51.100.8", ps5mac)) {
			t.Fatalf("unsafe source admitted: %s", src)
		}
	}
	for _, dst := range []string{"10.42.0.10", "10.42.0.5", "127.0.0.1", "224.0.0.1"} {
		if e.input(autoFrame("10.42.0.50", dst, ps5mac)) {
			t.Fatalf("unsafe destination: %s", dst)
		}
	}
	bad := autoFrame("10.42.0.50", "198.51.100.8", ps5mac)
	bad[22] ^= 1
	if e.input(bad) || len(e.deviceReports()) != 0 {
		t.Fatal("corrupt packet enrolled device")
	}
	a := netip.MustParseAddr("10.42.0.50")
	b := netip.MustParseAddr("10.42.0.60")
	p := e.acceptPeer(a, ps5mac)
	if p == nil {
		t.Fatal("automatic device not learned")
	}
	other := net.HardwareAddr{2, 6, 4, 3, 2, 1}
	if e.acceptPeer(a, other) != nil {
		t.Fatal("another MAC stole an enrolled IP")
	}
	if e.acceptPeer(b, ps5mac) != p || len(e.deviceReports()) != 1 || e.deviceReports()[0].IP != b.String() {
		t.Fatal("same device address change required configuration")
	}
	if e.acceptPeer(a, ps5mac) != p || e.addresses[a] != p {
		t.Fatal("existing flow reply mapping lost after IP change")
	}
	e.refreshLinkLocals("fe80::50%en1 02:01:02:03:04:05 en1\nfe80::60%en0 " + ps5mac.String() + " en0\n")
	if e.deviceReports()[0].LinkLocal != "fe80::60" {
		t.Fatal("admitted device did not acquire scoped IPv6 neighbor")
	}
}

func TestAutomaticAdmissionAndFilterBounds(t *testing.T) {
	c := autoConfig()
	c.IPv6 = true
	c.IPv6Prefixes = []string{"fd42:10:20:30::/64"}
	e, err := newEngine(c, mac, nil, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	for i := 0; i < maxAutoDevices; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("10.42.0.%d", 50+i))
		m := net.HardwareAddr{2, 0, 0, 0, 0, byte(i + 1)}
		if e.acceptPeer(ip, m) == nil {
			t.Fatal("device limit enforced too early")
		}
		c.Peers = append(c.Peers, peerSeed{IP: ip.String(), MAC: m.String()})
	}
	if e.acceptPeer(netip.MustParseAddr("10.42.0.200"), net.HardwareAddr{2, 0, 0, 0, 0, 200}) != nil {
		t.Fatal("device table unbounded")
	}
	c.Router = e.v6Router
	raw := captureFilters(c, mac)
	p := make([]bpf.RawInstruction, len(raw))
	for i, r := range raw {
		p[i] = bpf.RawInstruction{Op: r.Code, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	ins, ok := bpf.Disassemble(p)
	if !ok {
		t.Fatal("invalid maximum-size filter")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		src, dst string
		allowed  bool
	}{{"10.42.0.200", "198.51.100.8", true}, {"10.42.1.50", "198.51.100.8", false}, {"10.42.0.200", "10.42.0.10", false}, {"10.42.0.200", "10.42.0.55", false}} {
		n, err := vm.Run(autoFrame(tc.src, tc.dst, ps5mac))
		if err != nil || (n > 0) != tc.allowed {
			t.Fatalf("filter scope %v: %d %v", tc, n, err)
		}
	}
	f := make([]byte, 78)
	copy(f, mac)
	copy(f[6:], net.HardwareAddr{2, 0, 0, 0, 0, 32})
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	f[14] = 0x60
	if n, _ := vm.Run(f); n == 0 {
		t.Fatal("last admitted IPv6 device was filtered")
	}
	f[11] = 99
	if n, _ := vm.Run(f); n != 0 {
		t.Fatal("unknown IPv6 device was captured")
	}
}

func TestAutomaticHealthTargetsStayOnLAN(t *testing.T) {
	input := []string{"10.42.0.50", "10.42.0.50", "10.42.1.50", "10.42.0.10", "10.42.0.0", "10.42.0.255", "8.8.8.8", "::1"}
	b, _ := json.Marshal(input)
	targets, err := healthDeviceTargets(autoConfig(), base64.StdEncoding.EncodeToString(b))
	if err != nil || len(targets) != 1 || targets[0] != "10.42.0.50" {
		t.Fatalf("invalid automatic health targets: %v %v", targets, err)
	}
}
