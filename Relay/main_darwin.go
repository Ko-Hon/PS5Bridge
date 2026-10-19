package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func openCapture(cfg configuration, mac net.HardwareAddr, probe bool) (int, int, error) {
	fd := -1
	for i := 0; i < 256; i++ {
		n, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil {
			fd = n
			break
		}
		if err != unix.EBUSY {
			return -1, 0, fmt.Errorf("打开 BPF：%w", err)
		}
	}
	if fd < 0 {
		return -1, 0, fmt.Errorf("没有空闲的 BPF 设备")
	}
	fail := func(err error) (int, int, error) { unix.Close(fd); return -1, 0, err }
	if err := syscall.SetBpf(fd, []syscall.BpfInsn{{Code: syscall.BPF_RET | syscall.BPF_K, K: 0}}); err != nil {
		return fail(err)
	}
	// This changes only this capture descriptor, never PF, routes, or IP forwarding.
	if _, err := syscall.SetBpfBuflen(fd, 1<<20); err != nil {
		return fail(err)
	}
	if err := syscall.SetBpfInterface(fd, cfg.Interface); err != nil {
		return fail(err)
	}
	link, err := syscall.BpfDatalink(fd)
	if err != nil || link != syscall.DLT_EN10MB {
		return fail(fmt.Errorf("所选网络不支持以太网格式的 BPF 捕获"))
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		return fail(err)
	}
	if err := syscall.SetBpfHeadercmpl(fd, 1); err != nil {
		return fail(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 0); err != nil {
		return fail(err)
	}
	filter := captureFilters(cfg, mac)
	if probe {
		filter = []syscall.BpfInsn{{Code: syscall.BPF_RET | syscall.BPF_K, K: 0}}
	}
	if err := syscall.SetBpf(fd, filter); err != nil {
		return fail(err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return fail(err)
	}
	size, err := syscall.BpfBuflen(fd)
	if err != nil {
		return fail(err)
	}
	return fd, size, nil
}

func vpnDialer(index int) func(context.Context, string, string) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		var result error
		if err := c.Control(func(fd uintptr) {
			if network == "tcp6" || network == "udp6" {
				result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		}); err != nil {
			return err
		}
		return result
	}}
	return d.DialContext
}

func run() error {
	if len(os.Args) == 3 && os.Args[1] == "--ipv6-check" {
		name := os.Args[2]
		if len(name) < 5 || name[:4] != "utun" {
			return fmt.Errorf("需要指定 utun 出口")
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		if err = probeIPv6(ctx, vpnDialer(iface.Index)); err != nil {
			return err
		}
		fmt.Println("IPv6 HTTPS 已验证，套接字绑定指定 utun，无 IPv4 回退")
		return nil
	}
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "--health" {
		targets := ""
		if len(os.Args) == 5 {
			targets = os.Args[4]
		}
		return runHealth(os.Args[2], os.Args[3], targets)
	}
	if len(os.Args) != 6 || (os.Args[1] != "--run" && os.Args[1] != "--probe") {
		return fmt.Errorf("仅支持由桥接软件启动用户态引擎")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("BPF 捕获需要 macOS 管理员验证")
	}
	parentPID := os.Getppid()
	if parentPID <= 1 {
		return fmt.Errorf("缺少监护进程")
	}
	data, err := base64.StdEncoding.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	var cfg configuration
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	vpnName := os.Args[3]
	if len(vpnName) < 5 || vpnName[:4] != "utun" {
		return fmt.Errorf("VPN interface required")
	}
	uid, err := strconv.Atoi(os.Args[4])
	if err != nil || uid < 501 {
		return fmt.Errorf("invalid target uid")
	}
	gid, err := strconv.Atoi(os.Args[5])
	if err != nil || gid < 0 {
		return fmt.Errorf("invalid target gid")
	}
	lan, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return err
	}
	vpn, err := net.InterfaceByName(vpnName)
	if err != nil {
		return err
	}
	if net.ParseIP(cfg.Client).To4() == nil || len(lan.HardwareAddr) != 6 {
		return fmt.Errorf("invalid capture parameters")
	}
	if len(cfg.clients()) > 8 {
		return fmt.Errorf("设备过多")
	}
	for _, client := range cfg.clients() {
		if net.ParseIP(client).To4() == nil {
			return fmt.Errorf("invalid client IPv4")
		}
	}
	if os.Args[1] == "--run" {
		if err = prepareIPv6(&cfg, lan); err != nil {
			return err
		}
	}
	fd, size, err := openCapture(cfg, lan.HardwareAddr, os.Args[1] == "--probe")
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// Parse untrusted packets and open upstream sockets as the logged-in user.
	if err = unix.Setgroups(nil); err != nil {
		return err
	}
	if err = unix.Setgid(gid); err != nil {
		return err
	}
	if err = unix.Setuid(uid); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("privilege drop failed")
	}
	if os.Args[1] == "--probe" {
		return probeVPN(vpn.Index)
	}
	e, err := newEngine(cfg, lan.HardwareAddr, vpnDialer(vpn.Index), func(frame []byte) error { _, err := unix.Write(fd, frame); return err })
	if err != nil {
		return err
	}
	defer e.close()
	if cfg.IPv6 {
		cfg.Router = e.v6Router
		if err := syscall.SetBpf(fd, captureFilters(cfg, lan.HardwareAddr)); err != nil {
			return err
		}
		groupFD, err := joinIPv6Groups(lan.Index, e.v6Router)
		if err != nil {
			return fmt.Errorf("IPv6 邻居发现组加入失败：%w", err)
		}
		defer unix.Close(groupFD)
		e.v6Done = make(chan struct{})
		go e.runIPv6()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	enc := json.NewEncoder(os.Stdout)
	lastSample := time.Now()
	var lastUpload, lastDownload, sequence uint64
	emit := func() {
		now := time.Now()
		upload, download := e.stats.UploadBytes.Load(), e.stats.DownloadBytes.Load()
		elapsed := now.Sub(lastSample).Seconds()
		var upRate, downRate float64
		if elapsed > 0 {
			upRate = float64(upload-lastUpload) / elapsed
			downRate = float64(download-lastDownload) / elapsed
		}
		sequence++
		enc.Encode(map[string]any{"ready": true, "packets": e.stats.Packets.Load(), "replies": e.stats.Replies.Load(), "tcp": e.stats.TCP.Load(), "udp": e.stats.UDP.Load(), "failures": e.stats.Failures.Load(), "uid": os.Geteuid(), "uploadBytes": upload, "downloadBytes": download, "uploadRate": upRate, "downloadRate": downRate, "lastClientAt": float64(e.stats.LastClientAt.Load()) / 1000, "sequence": sequence, "connections": e.connectionReports(), "devices": e.deviceReports(), "ipv6Status": e.ipv6Status(), "ipv6Packets": e.stats.IPv6Packets.Load(), "ipv6Replies": e.stats.IPv6Replies.Load()})
		lastSample, lastUpload, lastDownload = now, upload, download
	}
	emit()
	defer func() { e.close(); emit() }()
	last := time.Now()
	lastPeers := ""
	buf := make([]byte, size)
	for ctx.Err() == nil {
		if os.Getppid() != parentPID {
			return nil
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(p, 250)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLNVAL|unix.POLLHUP) != 0 {
			return fmt.Errorf("BPF device disconnected")
		}
		if p[0].Revents&unix.POLLIN != 0 {
			n, err := unix.Read(fd, buf)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			if err := bpfRecords(buf[:n], func(frame []byte) { e.input(frame) }); err != nil {
				return err
			}
		}
		if time.Since(last) >= time.Second {
			if cfg.IPv6 {
				next := cfg
				next.Peers = nil
				key := ""
				for _, peer := range e.deviceReports() {
					if peer.MAC != "" {
						next.Peers = append(next.Peers, peerSeed{IP: peer.IP, MAC: peer.MAC})
						key += peer.IP + "/" + peer.MAC + ";"
					}
				}
				if key != lastPeers {
					if err := syscall.SetBpf(fd, captureFilters(next, lan.HardwareAddr)); err != nil {
						return fmt.Errorf("更新所选设备 IPv6 捕获范围：%w", err)
					}
					lastPeers = key
				}
			}
			emit()
			last = time.Now()
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probeVPN(index int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	dial := vpnDialer(index)
	c, err := dial(ctx, "tcp4", "1.1.1.1:443")
	if err != nil {
		return fmt.Errorf("VPN TCP 检测失败：%w", err)
	}
	secure := tls.Client(c, &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12})
	defer secure.Close()
	if err = secure.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("VPN TLS 检测失败：%w", err)
	}
	u, err := dial(ctx, "udp4", "1.1.1.1:53")
	if err != nil {
		return fmt.Errorf("VPN UDP 检测失败：%w", err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	// A fixed public test name; no captured console data or user identifiers.
	q := []byte{0x50, 0x35, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err = u.Write(q); err != nil {
		return err
	}
	b := make([]byte, 2048)
	n, err := u.Read(b)
	if err != nil {
		return fmt.Errorf("VPN UDP DNS 未收到回复：%w", err)
	}
	if n < 12 || b[0] != q[0] || b[1] != q[1] || b[2]&0x80 == 0 || b[3]&15 != 0 {
		return fmt.Errorf("VPN UDP DNS 返回无效响应")
	}
	_, err = io.WriteString(os.Stdout, fmt.Sprintf("BPF 权限正常；引擎已降权至 UID %d；VPN 绑定 TCP/TLS 和 UDP/DNS 均通过。检测期间未接收局域网设备数据。\n", os.Geteuid()))
	return err
}
