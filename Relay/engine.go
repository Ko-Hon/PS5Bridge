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
	"sync/atomic"
	"time"

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
	"gvisor.dev/gvisor/pkg/waiter"
)

type configuration struct {
	Interface         string     `json:"interface"`
	Gateway           string     `json:"gateway"`
	Mask              string     `json:"mask"`
	Client            string     `json:"client"`
	AdditionalClients []string   `json:"additionalClients,omitempty"`
	IPv6              bool       `json:"ipv6Enabled,omitempty"`
	Peers             []peerSeed `json:"-"`
	IPv6Prefixes      []string   `json:"-"`
	Router            netip.Addr `json:"-"`
}

type counters struct {
	Packets       atomic.Uint64
	Replies       atomic.Uint64
	TCP           atomic.Uint64
	UDP           atomic.Uint64
	Failures      atomic.Uint64
	UploadBytes   atomic.Uint64
	DownloadBytes atomic.Uint64
	LastClientAt  atomic.Int64
	IPv6Packets   atomic.Uint64
	IPv6Replies   atomic.Uint64
}

type engine struct {
	ctx           context.Context
	cancel        context.CancelFunc
	s             *stack.Stack
	link          *channel.Endpoint
	config        configuration
	client        netip.Addr
	subnet        netip.Prefix
	mac           net.HardwareAddr
	peerMu        sync.Mutex
	devices       map[netip.Addr]*devicePeer
	addresses     map[netip.Addr]*devicePeer
	byMAC         map[string]*devicePeer
	clientGateway netip.Addr
	v6Prefixes    []netip.Prefix
	v6Router      netip.Addr
	v6Ready       atomic.Bool
	v6Done        chan struct{}
	v6DAD         atomic.Bool
	v6Conflict    atomic.Bool
	v6Mu          sync.Mutex
	v6Error       string
	dial          func(context.Context, string, string) (net.Conn, error)
	send          func([]byte) error
	slots         chan struct{}
	connsMu       sync.Mutex
	conns         map[net.Conn]struct{}
	stats         counters
	endpoints     endpointRegistry
	names         nameCache
	outputDone    chan struct{}
	closeOnce     sync.Once
}

func newEngine(cfg configuration, mac net.HardwareAddr, dial func(context.Context, string, string) (net.Conn, error), send func([]byte) error) (*engine, error) {
	client, err := netip.ParseAddr(cfg.Client)
	if err != nil || !client.Is4() {
		return nil, fmt.Errorf("invalid client IPv4")
	}
	gw, err := netip.ParseAddr(cfg.Gateway)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("invalid gateway IPv4")
	}
	mask := net.ParseIP(cfg.Mask).To4()
	if mask == nil {
		return nil, fmt.Errorf("invalid mask")
	}
	bits, size := net.IPMask(mask).Size()
	if size != 32 || bits < 8 || bits > 30 || len(mac) != 6 {
		return nil, fmt.Errorf("invalid subnet or MAC")
	}
	subnet := netip.PrefixFrom(gw, bits).Masked()
	if !subnet.Contains(client) || client == gw {
		return nil, fmt.Errorf("client must be on LAN")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &engine{ctx: ctx, cancel: cancel, config: cfg, client: client, subnet: subnet, mac: append(net.HardwareAddr(nil), mac...), dial: dial, send: send, slots: make(chan struct{}, 512), conns: make(map[net.Conn]struct{}), outputDone: make(chan struct{})}
	e.clientGateway = gw
	if err := e.initDevices(); err != nil {
		cancel()
		return nil, err
	}
	if err := e.initIPv6(); err != nil {
		cancel()
		return nil, err
	}
	e.link = channel.New(1024, 1280, "")
	e.s = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	if err := e.s.CreateNIC(1, e.link); err != nil {
		cancel()
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	e.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	go e.output()
	if err := e.s.SetPromiscuousMode(1, true); err != nil {
		e.close()
		return nil, fmt.Errorf("promiscuous: %s", err)
	}
	if err := e.s.SetSpoofing(1, true); err != nil {
		e.close()
		return nil, fmt.Errorf("spoofing: %s", err)
	}
	tf := tcp.NewForwarder(e.s, 0, 128, e.forwardTCP)
	uf := udp.NewForwarder(e.s, e.forwardUDP)
	e.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	e.s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	return e, nil
}

// Only selected devices enter Netstack; the physical NIC is never promiscuous.
func (e *engine) input(frame []byte) bool {
	if len(frame) < 34 || e.ctx.Err() != nil {
		return false
	}
	ip := frame[14:]
	etherType := binary.BigEndian.Uint16(frame[12:14])
	var src, dst netip.Addr
	var proto tcpip.NetworkProtocolNumber
	var length int
	switch etherType {
	case 0x0800:
		if !bytes.Equal(frame[:6], e.mac) || ip[0]>>4 != 4 {
			return false
		}
		hlen := int(ip[0]&15) * 4
		length = int(binary.BigEndian.Uint16(ip[2:4]))
		if hlen < 20 || length < hlen || length > len(ip) || (ip[9] != 6 && ip[9] != 17) {
			return false
		}
		src = netip.AddrFrom4([4]byte(ip[12:16]))
		dst = netip.AddrFrom4([4]byte(ip[16:20]))
		if e.subnet.Contains(dst) {
			return false
		}
		proto = ipv4.ProtocolNumber
	case 0x86dd:
		if !e.config.IPv6 || len(ip) < 40 || ip[0]>>4 != 6 {
			return false
		}
		length = 40 + int(binary.BigEndian.Uint16(ip[4:6]))
		if length > len(ip) {
			return false
		}
		ip = ip[:length]
		if ip[6] == 58 {
			if e.observeDAD(frame, ip) {
				return true
			}
			return e.ipv6Control(frame, ip)
		}
		if !e.v6Ready.Load() || !bytes.Equal(frame[:6], e.mac) || !ipv6Transport(ip) {
			return false
		}
		src = netip.AddrFrom16([16]byte(ip[8:24]))
		dst = netip.AddrFrom16([16]byte(ip[24:40]))
		if dst.Is4In6() || e.onIPv6LAN(dst) {
			return false
		}
		proto = ipv6.ProtocolNumber
	default:
		return false
	}
	if !dst.IsGlobalUnicast() || dst.IsLoopback() || dst.IsLinkLocalUnicast() {
		return false
	}
	peer := e.acceptPeer(src, frame[6:12])
	if peer == nil {
		return false
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), ip[:length]...))})
	e.link.InjectInbound(proto, pkt)
	pkt.DecRef()
	e.stats.Packets.Add(1)
	e.stats.UploadBytes.Add(uint64(length))
	peer.upload.Add(uint64(length))
	now := time.Now().UnixMilli()
	e.stats.LastClientAt.Store(now)
	peer.last.Store(now)
	if proto == ipv6.ProtocolNumber {
		e.stats.IPv6Packets.Add(1)
		peer.v6packets.Add(1)
	}
	return true
}

// Bound extension parsing before handing packets to the IPv6 implementation.
func ipv6Transport(ip []byte) bool {
	next, offset := ip[6], 40
	for i := 0; i < 8; i++ {
		switch next {
		case 6, 17:
			return true
		case 44:
			if offset+8 > len(ip) {
				return false
			}
			// Subsequent fragments contain no complete transport header.
			if binary.BigEndian.Uint16(ip[offset+2:])&0xfff8 != 0 {
				return ip[offset] == 6 || ip[offset] == 17
			}
			next, offset = ip[offset], offset+8
		case 0, 60:
			if offset+2 > len(ip) {
				return false
			}
			n := (int(ip[offset+1]) + 1) * 8
			if offset+n > len(ip) {
				return false
			}
			next, offset = ip[offset], offset+n
		default:
			return false
		}
	}
	return false
}

func (e *engine) output() {
	defer close(e.outputDone)
	for {
		pkt := e.link.ReadContext(e.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		ip := append([]byte(nil), v.AsSlice()...)
		v.Release()
		pkt.DecRef()
		if len(ip) < 20 {
			continue
		}
		etherType := uint16(0x0800)
		dst := netip.AddrFrom4([4]byte(ip[16:20]))
		if ip[0]>>4 == 6 {
			if len(ip) < 40 {
				continue
			}
			etherType = 0x86dd
			dst = netip.AddrFrom16([16]byte(ip[24:40]))
		}
		e.peerMu.Lock()
		peer := e.addresses[dst]
		var mac net.HardwareAddr
		if peer != nil {
			mac = append(net.HardwareAddr(nil), peer.mac...)
		}
		e.peerMu.Unlock()
		if len(mac) != 6 {
			continue
		}
		frame := make([]byte, 14+len(ip))
		copy(frame, mac)
		copy(frame[6:], e.mac)
		binary.BigEndian.PutUint16(frame[12:], etherType)
		copy(frame[14:], ip)
		if err := e.send(frame); err != nil {
			e.stats.Failures.Add(1)
		} else {
			e.stats.Replies.Add(1)
			e.stats.DownloadBytes.Add(uint64(len(ip)))
			peer.download.Add(uint64(len(ip)))
			if etherType == 0x86dd {
				e.stats.IPv6Replies.Add(1)
			}
		}
	}
}

func flowNetwork(id stack.TransportEndpointID, transport string) string {
	if id.LocalAddress.Len() == 16 {
		return transport + "6"
	}
	return transport + "4"
}
func (e *engine) sourceDevice(addr tcpip.Address) string {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	if p := e.addresses[ip]; p != nil {
		return p.ip.String()
	}
	return ip.String()
}

func (e *engine) acquire() bool {
	select {
	case e.slots <- struct{}{}:
		return true
	default:
		e.stats.Failures.Add(1)
		return false
	}
}
func (e *engine) track(c net.Conn) bool {
	e.connsMu.Lock()
	defer e.connsMu.Unlock()
	if e.ctx.Err() != nil {
		c.Close()
		return false
	}
	e.conns[c] = struct{}{}
	return true
}
func (e *engine) untrack(c net.Conn) {
	c.Close()
	e.connsMu.Lock()
	delete(e.conns, c)
	e.connsMu.Unlock()
}
func address(id stack.TransportEndpointID) string {
	return net.JoinHostPort(net.IP(id.LocalAddress.AsSlice()).String(), fmt.Sprint(id.LocalPort))
}

func (e *engine) forwardTCP(r *tcp.ForwarderRequest) {
	if !e.acquire() {
		r.Complete(true)
		return
	}
	go func() {
		defer func() { <-e.slots }()
		target := address(r.ID())
		key := e.endpoints.beginFrom("TCP", target, e.sourceDevice(r.ID().RemoteAddress))
		defer e.endpoints.finish(key)
		began := time.Now()
		host, err := e.dial(e.ctx, flowNetwork(r.ID(), "tcp"), target)
		e.endpoints.dialResult(key, time.Since(began), err)
		if err != nil {
			e.stats.Failures.Add(1)
			r.Complete(true)
			return
		}
		if !e.track(host) {
			r.Complete(true)
			return
		}
		defer e.untrack(host)
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		guest := gonet.NewTCPConn(&wq, ep)
		if !e.track(guest) {
			return
		}
		defer e.untrack(guest)
		e.stats.TCP.Add(1)
		var upload, download io.Reader = guest, host
		_, port, _ := net.SplitHostPort(target)
		if port == "53" {
			dns := &dnsObserver{cache: &e.names}
			up, down := &dnsStream{feed: dns.query}, &dnsStream{feed: dns.reply}
			upload = &observedReader{Reader: guest, observe: up.observe}
			download = &observedReader{Reader: host, observe: down.observe}
		} else {
			observer := &clientNameObserver{found: func(name, source string) { e.endpoints.setDomain(key, name, source) }}
			upload = &observedReader{Reader: guest, observe: observer.observe}
		}
		done := make(chan struct{})
		go func() {
			io.Copy(host, upload)
			if c, ok := host.(interface{ CloseWrite() error }); ok {
				c.CloseWrite()
			}
			close(done)
		}()
		io.Copy(guest, download)
		guest.CloseWrite()
		select {
		case <-done:
		case <-e.ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}()
}

func (e *engine) forwardUDP(r *udp.ForwarderRequest) bool {
	if !e.acquire() {
		return false
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		<-e.slots
		return false
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer func() { <-e.slots }()
		if !e.track(guest) {
			return
		}
		defer e.untrack(guest)
		target := address(r.ID())
		key := e.endpoints.beginFrom("UDP", target, e.sourceDevice(r.ID().RemoteAddress))
		defer e.endpoints.finish(key)
		host, err := e.dial(e.ctx, flowNetwork(r.ID(), "udp"), target)
		e.endpoints.dialResult(key, 0, err)
		if err != nil {
			e.stats.Failures.Add(1)
			return
		}
		if !e.track(host) {
			return
		}
		defer e.untrack(host)
		e.stats.UDP.Add(1)
		var dns *dnsObserver
		if _, port, _ := net.SplitHostPort(target); port == "53" {
			dns = &dnsObserver{cache: &e.names}
		}
		done := make(chan struct{})
		// Preserve datagram boundaries. Each flow has an idle timeout and a bounded slot.
		go func() {
			defer close(done)
			buf := make([]byte, 65535)
			for {
				guest.SetReadDeadline(time.Now().Add(2 * time.Minute))
				n, err := guest.Read(buf)
				if err != nil {
					return
				}
				host.SetReadDeadline(time.Now().Add(2 * time.Minute))
				if dns != nil {
					dns.query(buf[:n])
				}
				if _, err = host.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 65535)
		for {
			host.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := host.Read(buf)
			if err != nil {
				return
			}
			if _, err = guest.Write(buf[:n]); err != nil {
				return
			}
			if dns != nil {
				dns.reply(buf[:n])
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	return true
}

func (e *engine) close() {
	e.closeOnce.Do(func() {
		e.cancel()
		if e.v6Done != nil {
			<-e.v6Done
		}
		e.advertiseIPv6(true)
		e.connsMu.Lock()
		for c := range e.conns {
			c.Close()
		}
		e.connsMu.Unlock()
		e.s.Destroy()
		e.link.Close()
		<-e.outputDone
	})
}

// Darwin arm64 uses 32-bit timeval fields in BPF record headers and 4-byte alignment.
// Lengths come from the kernel but are checked before any slicing.
func bpfRecords(data []byte, receive func([]byte)) error {
	for offset := 0; offset < len(data); {
		if len(data)-offset < 18 {
			return fmt.Errorf("short BPF header")
		}
		h := data[offset:]
		caplen := int(binary.LittleEndian.Uint32(h[8:12]))
		datalen := int(binary.LittleEndian.Uint32(h[12:16]))
		hlen := int(binary.LittleEndian.Uint16(h[16:18]))
		if hlen < 18 || hlen > len(h) || caplen < 14 || caplen > 65535 || datalen > 65535 || caplen > datalen || caplen > len(h)-hlen {
			return fmt.Errorf("invalid BPF record lengths")
		}
		if caplen == datalen {
			receive(h[hlen : hlen+caplen])
		}
		end := offset + hlen + caplen
		if end == len(data) {
			return nil
		}
		offset = (end + 3) &^ 3
	}
	return nil
}
