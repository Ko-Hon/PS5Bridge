package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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

func captureFilter(client net.IP, mac net.HardwareAddr) []syscall.BpfInsn {
	return []syscall.BpfInsn{
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 12},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: 0x0800, Jf: 7},
		{Code: syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS, K: 26},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: binary.BigEndian.Uint32(client.To4()), Jf: 5},
		{Code: syscall.BPF_LD | syscall.BPF_W | syscall.BPF_ABS, K: 0},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: binary.BigEndian.Uint32(mac[:4]), Jf: 3},
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 4},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, K: uint32(binary.BigEndian.Uint16(mac[4:])), Jf: 1},
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 65535},
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},
	}
}

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
	filter := captureFilter(net.ParseIP(cfg.Client), mac)
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
		if err := c.Control(func(fd uintptr) { result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index) }); err != nil {
			return err
		}
		return result
	}}
	return d.DialContext
}

func run() error {
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
		enc.Encode(map[string]any{"ready": true, "packets": e.stats.Packets.Load(), "replies": e.stats.Replies.Load(), "tcp": e.stats.TCP.Load(), "udp": e.stats.UDP.Load(), "failures": e.stats.Failures.Load(), "uid": os.Geteuid(), "uploadBytes": upload, "downloadBytes": download, "uploadRate": upRate, "downloadRate": downRate, "lastClientAt": float64(e.stats.LastClientAt.Load()) / 1000, "sequence": sequence, "connections": e.connectionReports()})
		lastSample, lastUpload, lastDownload = now, upload, download
	}
	emit()
	defer func() { e.close(); emit() }()
	last := time.Now()
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
