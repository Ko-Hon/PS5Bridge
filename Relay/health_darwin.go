package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type healthReport struct {
	Config             configuration `json:"config"`
	VPN                string        `json:"vpn"`
	LANReady           bool          `json:"lanReady"`
	PS5Reachable       bool          `json:"ps5Reachable"`
	PS5Latency         float64       `json:"ps5Latency"`
	VPNReachable       bool          `json:"vpnReachable"`
	GooglePing         bool          `json:"googlePing"`
	GoogleLatency      float64       `json:"googleLatency"`
	VPNDetail          string        `json:"vpnDetail"`
	CheckedAt          float64       `json:"checkedAt"`
	GoogleHTTPSLatency *float64      `json:"googleHTTPSLatency,omitempty"`
	ServerPings        []serverPing  `json:"serverPings"`
}

type serverPing struct {
	IP        string   `json:"ip"`
	Latency   *float64 `json:"latency,omitempty"`
	CheckedAt float64  `json:"checkedAt"`
}

func serverTargets(encoded string) ([]string, error) {
	if encoded == "" {
		return nil, nil
	}
	if len(encoded) > 4096 {
		return nil, fmt.Errorf("too many health targets")
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var input []string
	if err = json.Unmarshal(b, &input); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var targets []string
	for _, host := range input {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		host = ip.String()
		if !seen[host] {
			targets = append(targets, host)
			seen[host] = true
		}
		if len(targets) == 12 {
			break
		}
	}
	return targets, nil
}

func probeServers(ctx context.Context, targets []string, ping func(context.Context, string) (float64, error)) []serverPing {
	rows := make([]serverPing, len(targets))
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, host := range targets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			rows[i].IP = host
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			c, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			if n, err := ping(c, host); err == nil {
				rows[i].Latency = &n
			}
			rows[i].CheckedAt = float64(time.Now().UnixMilli()) / 1000
		}(i, host)
	}
	wg.Wait()
	return rows
}

func echoRequest(nonce []byte, seq uint16) []byte {
	b := make([]byte, 8+len(nonce))
	b[0] = 8
	binary.BigEndian.PutUint16(b[4:], uint16(os.Getpid()))
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], nonce)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[2:], ^uint16(sum))
	return b
}

func isEchoReply(b, nonce []byte, seq uint16) bool {
	if len(b) >= 20 && b[0]>>4 == 4 {
		hlen := int(b[0]&15) * 4
		if hlen < 20 || hlen > len(b) {
			return false
		}
		b = b[hlen:]
	}
	return len(b) == 8+len(nonce) && b[0] == 0 && b[1] == 0 && binary.BigEndian.Uint16(b[6:8]) == seq && bytes.Equal(b[8:], nonce)
}

// An unprivileged ICMP datagram socket; never invokes a shell or opens BPF.
func pingBound(ctx context.Context, index int, target string) (float64, error) {
	ip, err := netip.ParseAddr(target)
	if err != nil || !ip.Is4() || index <= 0 {
		return 0, fmt.Errorf("invalid ping destination/interface")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index); err != nil {
		return 0, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		return 0, err
	}
	if err = unix.Connect(fd, &unix.SockaddrInet4{Addr: ip.As4()}); err != nil {
		return 0, err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return 0, err
	}
	seq := binary.BigEndian.Uint16(nonce)
	began := time.Now()
	if _, err = unix.Write(fd, echoRequest(nonce, seq)); err != nil {
		return 0, err
	}
	b := make([]byte, 2048)
	for ctx.Err() == nil {
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(p, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, fmt.Errorf("ICMP socket unavailable")
		}
		if p[0].Revents&unix.POLLIN != 0 {
			n, err := unix.Read(fd, b)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return 0, err
			}
			if isEchoReply(b[:n], nonce, seq) {
				return float64(time.Since(began).Microseconds()) / 1000, nil
			}
		}
	}
	return 0, ctx.Err()
}

func googleHTTPS(ctx context.Context, index int) error {
	transport := &http.Transport{DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		return vpnDialer(index)(c, "tcp4", address)
	}, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.google.com/generate_204", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("Google HTTP %d", resp.StatusCode)
	}
	return nil
}

func vpnHealth(ctx context.Context, ping func(context.Context) (float64, error), https func(context.Context) error) (bool, bool, float64, string) {
	var pingOK bool
	var latency float64
	var tlsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		n, err := ping(pctx)
		pingOK = err == nil
		latency = n
	}()
	go func() { defer wg.Done(); tlsErr = https(ctx) }()
	wg.Wait()
	if tlsErr == nil {
		if pingOK {
			return true, true, latency, "Google Ping 有响应 · HTTPS 正常"
		}
		return true, false, 0, "Google HTTPS 正常 · Ping 无响应"
	}
	if pingOK {
		return false, true, latency, "Google Ping 有响应，HTTPS 检测失败：" + tlsErr.Error()
	}
	return false, false, 0, "Google 连通性检测失败：" + tlsErr.Error()
}

func runHealth(encoded, vpnName, encodedTargets string) error {
	targets, err := serverTargets(encodedTargets)
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	var cfg configuration
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	report := healthReport{Config: cfg, VPN: vpnName, VPNDetail: "未检测到 VPN 隧道"}
	lan, err := net.InterfaceByName(cfg.Interface)
	if err == nil && lan.Flags&net.FlagUp != 0 && lan.Flags&net.FlagRunning != 0 {
		addrs, _ := lan.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().String() == cfg.Gateway {
				report.LANReady = true
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6500*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	if client, err := netip.ParseAddr(cfg.Client); report.LANReady && err == nil && client.Is4() && client.IsPrivate() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			n, err := pingBound(c, lan.Index, cfg.Client)
			report.PS5Reachable = err == nil
			report.PS5Latency = n
		}()
	}
	if vpn, err := net.InterfaceByName(vpnName); err == nil && vpn.Flags&net.FlagUp != 0 && len(vpnName) > 4 && vpnName[:4] == "utun" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report.VPNReachable, report.GooglePing, report.GoogleLatency, report.VPNDetail = vpnHealth(ctx, func(c context.Context) (float64, error) { return pingBound(c, vpn.Index, "8.8.8.8") }, func(c context.Context) error {
				began := time.Now()
				err := googleHTTPS(c, vpn.Index)
				if err == nil {
					n := float64(time.Since(began).Microseconds()) / 1000
					report.GoogleHTTPSLatency = &n
				}
				return err
			})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			report.ServerPings = probeServers(ctx, targets, func(c context.Context, host string) (float64, error) { return pingBound(c, vpn.Index, host) })
		}()
	}
	wg.Wait()
	report.CheckedAt = float64(time.Now().UnixMilli()) / 1000
	return json.NewEncoder(os.Stdout).Encode(report)
}
