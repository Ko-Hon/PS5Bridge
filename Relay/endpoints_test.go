package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEndpointMeasurementsAndLifecycle(t *testing.T) {
	var r endpointRegistry
	a := r.begin("TCP", "1.1.1.1:443")
	b := r.begin("TCP", "1.1.1.1:443")
	u := r.begin("UDP", "8.8.8.8:53")
	r.dialResult(a, 42*time.Millisecond, nil)
	r.dialResult(u, time.Millisecond, nil)
	rows := r.snapshot()
	if len(rows) != 2 {
		t.Fatalf("expected grouped destinations: %+v", rows)
	}
	for _, row := range rows {
		if row.Protocol == "TCP" && (row.IP != "1.1.1.1" || row.Port != 443 || row.Active != 2 || row.ConnectLatency == nil || *row.ConnectLatency != 42) {
			t.Fatalf("TCP metadata: %+v", row)
		}
		if row.Protocol == "UDP" && row.ConnectLatency != nil {
			t.Fatal("local UDP connect was presented as latency")
		}
	}
	r.finish(a)
	r.finish(b)
	r.dialResult(u, 0, fmt.Errorf("network unavailable"))
	r.finish(u)
	for _, row := range r.snapshot() {
		if row.Active != 0 {
			t.Fatal("completed connection still active")
		}
		if row.Protocol == "UDP" && !row.DialFailed {
			t.Fatal("failure hidden")
		}
	}
	if r.begin("TCP", "bad:443") != "" || r.begin("UDP", "1.1.1.1:0") != "" {
		t.Fatal("invalid endpoint accepted")
	}
}

func TestEndpointBoundsAndConcurrentSnapshots(t *testing.T) {
	var r endpointRegistry
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				key := r.begin("TCP", fmt.Sprintf("203.0.113.%d:%d", i+1, j+1))
				r.dialResult(key, time.Millisecond, nil)
				r.snapshot()
				r.finish(key)
			}
		}(i)
	}
	wg.Wait()
	if len(r.snapshot()) != 12 || len(r.entries) > 128 {
		t.Fatalf("unbounded history: %d", len(r.entries))
	}
	for _, row := range r.entries {
		row.Updated -= 61
	}
	if len(r.snapshot()) != 0 {
		t.Fatal("expired destinations retained")
	}
}
