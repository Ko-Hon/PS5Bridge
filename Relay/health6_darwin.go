package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

type deviceHealth struct {
	IP        string  `json:"ip"`
	Reachable bool    `json:"reachable"`
	Latency   float64 `json:"latency"`
}

func isEchoReply6(b, nonce []byte, seq uint16) bool {
	if len(b) >= 40 && b[0]>>4 == 6 {
		if b[6] != 58 {
			return false
		}
		b = b[40:]
	}
	return len(b) == 8+len(nonce) && b[0] == 129 && b[1] == 0 && binary.BigEndian.Uint16(b[6:8]) == seq && bytes.Equal(b[8:], nonce)
}

func ping6Bound(ctx context.Context, index int, ip netip.Addr) (float64, error) {
	if index <= 0 || !ip.Is6() || !ip.IsGlobalUnicast() {
		return 0, fmt.Errorf("invalid IPv6 ping target")
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index); err != nil {
		return 0, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		return 0, err
	}
	if err = unix.Connect(fd, &unix.SockaddrInet6{Addr: ip.As16()}); err != nil {
		return 0, err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return 0, err
	}
	seq := binary.BigEndian.Uint16(nonce)
	b := make([]byte, 8+len(nonce))
	b[0] = 128
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], nonce)
	began := time.Now()
	if _, err = unix.Write(fd, b); err != nil {
		return 0, err
	}
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err = unix.Poll(poll, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, fmt.Errorf("IPv6 ICMP socket unavailable")
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			n, err := unix.Read(fd, buf)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return 0, err
			}
			if isEchoReply6(buf[:n], nonce, seq) {
				return float64(time.Since(began).Microseconds()) / 1000, nil
			}
		}
	}
	return 0, ctx.Err()
}
