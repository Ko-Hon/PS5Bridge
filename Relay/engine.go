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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type configuration struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Mask      string `json:"mask"`
	Client    string `json:"client"`
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
}

type engine struct {
	ctx        context.Context
	cancel     context.CancelFunc
	s          *stack.Stack
	link       *channel.Endpoint
	config     configuration
	client     netip.Addr
	subnet     netip.Prefix
	mac        net.HardwareAddr
	peerMu     sync.Mutex
	peer       net.HardwareAddr
	dial       func(context.Context, string, string) (net.Conn, error)
	send       func([]byte) error
	slots      chan struct{}
	connsMu    sync.Mutex
	conns      map[net.Conn]struct{}
	stats      counters
	endpoints  endpointRegistry
	names      nameCache
	outputDone chan struct{}
	closeOnce  sync.Once
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
	e.link = channel.New(1024, 1400, "")
	e.s = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	if err := e.s.CreateNIC(1, e.link); err != nil {
		cancel()
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	e.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
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

// Only the selected console's IPv4 frames addressed to this Mac enter Netstack.
// Local LAN traffic stays with the OS; the capture interface is never promiscuous.
func (e *engine) input(frame []byte) bool {
	if len(frame) < 34 || !bytes.Equal(frame[:6], e.mac) || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return false
	}
	ip := frame[14:]
	hlen := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || hlen < 20 || len(ip) < hlen {
		return false
	}
	length := int(binary.BigEndian.Uint16(ip[2:4]))
	if length < hlen || length > len(ip) {
		return false
	}
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))
	if src != e.client || !dst.IsGlobalUnicast() || dst.IsLoopback() || dst.IsLinkLocalUnicast() || e.subnet.Contains(dst) || (ip[9] != 6 && ip[9] != 17) {
		return false
	}
	sourceMAC := frame[6:12]
	if sourceMAC[0]&1 != 0 || bytes.Equal(sourceMAC, e.mac) || bytes.Equal(sourceMAC, make([]byte, 6)) {
		return false
	}
	e.peerMu.Lock()
	if e.peer == nil {
		e.peer = append(net.HardwareAddr(nil), sourceMAC...)
	}
	samePeer := bytes.Equal(e.peer, sourceMAC)
	e.peerMu.Unlock()
	if !samePeer || e.ctx.Err() != nil {
		return false
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), ip[:length]...))})
	e.link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
	e.stats.Packets.Add(1)
	e.stats.UploadBytes.Add(uint64(length))
	e.stats.LastClientAt.Store(time.Now().UnixMilli())
	return true
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
		if len(ip) < 20 || netip.AddrFrom4([4]byte(ip[16:20])) != e.client {
			continue
		}
		e.peerMu.Lock()
		peer := append([]byte(nil), e.peer...)
		e.peerMu.Unlock()
		if len(peer) != 6 {
			continue
		}
		frame := make([]byte, 14+len(ip))
		copy(frame[:6], peer)
		copy(frame[6:12], e.mac)
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		copy(frame[14:], ip)
		if err := e.send(frame); err != nil {
			e.stats.Failures.Add(1)
		} else {
			e.stats.Replies.Add(1)
			e.stats.DownloadBytes.Add(uint64(len(ip)))
		}
	}
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
		key := e.endpoints.begin("TCP", target)
		defer e.endpoints.finish(key)
		began := time.Now()
		host, err := e.dial(e.ctx, "tcp4", target)
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
		key := e.endpoints.begin("UDP", target)
		defer e.endpoints.finish(key)
		host, err := e.dial(e.ctx, "udp4", target)
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
