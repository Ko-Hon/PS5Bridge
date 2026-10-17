package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerProbeBoundsAndNoInventedLatency(t *testing.T) {
	input := []string{"1.1.1.1", "1.1.1.1", "127.0.0.1", "10.42.0.50", "224.0.0.1", "::1", "example.com", "8.8.8.8"}
	for i := 1; i < 30; i++ {
		input = append(input, fmt.Sprintf("203.0.113.%d", i))
	}
	b, _ := json.Marshal(input)
	targets, err := serverTargets(base64.StdEncoding.EncodeToString(b))
	if err != nil || len(targets) != 12 || targets[0] != "1.1.1.1" || targets[1] != "8.8.8.8" {
		t.Fatalf("unsafe/unbounded targets: %v %v", targets, err)
	}
	var running, peak atomic.Int32
	rows := probeServers(context.Background(), targets, func(ctx context.Context, host string) (float64, error) {
		n := running.Add(1)
		defer running.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		if host == "1.1.1.1" {
			return 0, fmt.Errorf("no response")
		}
		return 23.5, nil
	})
	if peak.Load() > 4 || len(rows) != 12 || rows[0].Latency != nil || rows[1].Latency == nil || *rows[1].Latency != 23.5 {
		t.Fatalf("incorrect probe results: %+v", rows)
	}
	if _, err := serverTargets("not base64"); err == nil {
		t.Fatal("malformed targets accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	probeServers(ctx, targets, func(c context.Context, _ string) (float64, error) { <-c.Done(); return 0, c.Err() })
	if time.Since(began) > time.Second {
		t.Fatal("cancelled probes did not stop")
	}
}

func TestVPNLampRequiresGoogleHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name            string
		pingOK, httpsOK bool
	}{{"both reachable", true, true}, {"ICMP blocked", false, true}, {"synthetic ping without Internet", true, false}, {"offline", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			reachable, pingOK, _, detail := vpnHealth(context.Background(), func(context.Context) (float64, error) {
				if tc.pingOK {
					return 42, nil
				}
				return 0, fmt.Errorf("ICMP blocked")
			}, func(context.Context) error {
				if tc.httpsOK {
					return nil
				}
				return fmt.Errorf("offline")
			})
			if reachable != tc.httpsOK || pingOK != tc.pingOK || detail == "" {
				t.Fatalf("incorrect lamp: reachable=%v ping=%v detail=%s", reachable, pingOK, detail)
			}
		})
	}
}

func TestICMPReplyValidation(t *testing.T) {
	nonce := []byte("ps5-bridge-test!")
	seq := uint16(0x5135)
	request := echoRequest(nonce, seq)
	if isEchoReply(request, nonce, seq) {
		t.Fatal("request mistaken for response")
	}
	reply := append([]byte(nil), request...)
	reply[0] = 0
	if !isEchoReply(reply, nonce, seq) {
		t.Fatal("valid datagram response rejected")
	}
	if isEchoReply(reply, nonce, seq+1) || isEchoReply(reply, []byte("wrong payload"), seq) {
		t.Fatal("unrelated response accepted")
	}
	ip := make([]byte, 20)
	ip[0] = 0x45
	if !isEchoReply(append(ip, reply...), nonce, seq) {
		t.Fatal("Darwin response with IPv4 header rejected")
	}
	for i := 0; i < len(reply); i++ {
		if isEchoReply(reply[:i], nonce, seq) {
			t.Fatal("short response accepted")
		}
	}
}

func TestICMPDoesNotFallbackFromInvalidVPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := pingBound(ctx, 0x7fffffff, "127.0.0.1"); err == nil {
		t.Fatal("invalid VPN binding accepted")
	}
}
