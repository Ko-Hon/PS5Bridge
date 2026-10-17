package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func dnsPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("Game.Example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{q}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: true}, Questions: []dnsmessage.Question{q}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.example.test.")}},
		{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("edge.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 8}}},
		{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}},
	}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query, reply
}

func TestDNSNamesRequireMatchingQueryAndExpire(t *testing.T) {
	query, reply := dnsPair(t)
	var cache nameCache
	d := dnsObserver{cache: &cache}
	d.reply(reply)
	if len(cache.lookup("203.0.113.8", time.Now())) != 0 {
		t.Fatal("unsolicited DNS response trusted")
	}
	d.query(query)
	wrong := append([]byte(nil), reply...)
	wrong[1]++
	d.reply(wrong)
	if len(cache.lookup("203.0.113.8", time.Now())) != 0 {
		t.Fatal("unmatched response trusted")
	}
	d.reply(reply)
	if names := cache.lookup("203.0.113.8", time.Now()); len(names) != 1 || names[0] != "game.example.test" {
		t.Fatalf("CNAME association missing: %v", names)
	}
	if len(cache.lookup("203.0.113.9", time.Now())) != 0 {
		t.Fatal("unrelated answer accepted")
	}
	if len(cache.lookup("203.0.113.8", time.Now().Add(11*time.Second))) != 0 {
		t.Fatal("CNAME TTL ignored")
	}
	cache.put("203.0.113.8", "zero.example.test", 0, time.Now())
	if len(cache.lookup("203.0.113.8", time.Now())) != 0 {
		t.Fatal("zero TTL cached")
	}
}

func TestDNSCacheBoundsAndSharedIPNames(t *testing.T) {
	var cache nameCache
	for i := 0; i < 1100; i++ {
		cache.put(fmt.Sprint(i), "game.example.test", 60, time.Now())
	}
	if len(cache.entries) > 1024 {
		t.Fatal("unbounded IP cache")
	}
	for i := 0; i < 10; i++ {
		cache.put("203.0.113.8", fmt.Sprintf("game%d.example.test", i), 60, time.Now())
	}
	if len(cache.lookup("203.0.113.8", time.Now())) != 4 {
		t.Fatal("aliases unbounded")
	}
	var r endpointRegistry
	key := r.begin("TCP", "203.0.113.8:443")
	r.setDomain(key, "one.example.test", "TLS SNI")
	r.setDomain(key, "two.example.test", "TLS SNI")
	row := r.snapshot()[0]
	if row.Domain != "two.example.test" || len(row.Aliases) != 2 {
		t.Fatal("shared target domain ambiguity hidden")
	}
}

func TestDNSTCPFramingAndInvalidPayloads(t *testing.T) {
	q, r := dnsPair(t)
	var cache nameCache
	d := dnsObserver{cache: &cache}
	up, down := dnsStream{feed: d.query}, dnsStream{feed: d.reply}
	frame := func(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
	for _, b := range frame(q) {
		up.observe([]byte{b})
	}
	for _, b := range frame(r) {
		down.observe([]byte{b})
	}
	if len(cache.lookup("203.0.113.8", time.Now())) != 1 {
		t.Fatal("split DNS over TCP lost")
	}
	rng := rand.New(rand.NewSource(20261017))
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		d.query(b)
		d.reply(b)
		clientName(b)
	}
}

func testClientHello(name string) []byte {
	vector := func(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }
	server := append([]byte{0}, vector([]byte(name))...)
	ext := append([]byte{0, 0}, vector(vector(server))...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = append(body, vector(ext)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestTLSAndHTTPNameStreamBoundaries(t *testing.T) {
	hello := testClientHello("Game.Example.test")
	record := func(b []byte) []byte { return append([]byte{22, 3, 1, byte(len(b) >> 8), byte(len(b))}, b...) }
	data := append(record(hello[:15]), record(hello[15:])...)
	got := ""
	o := clientNameObserver{found: func(n, s string) {
		got = n
		if s != "TLS SNI" {
			t.Fatal(s)
		}
	}}
	for _, b := range data {
		o.observe([]byte{b})
	}
	if got != "game.example.test" {
		t.Fatalf("fragmented TLS name lost: %q", got)
	}
	if n, s, done := clientName([]byte("GET /private/path HTTP/1.1\r\nHost: Game.Example.test:8080\r\n\r\n")); n != "game.example.test" || s != "HTTP Host" || !done {
		t.Fatal("HTTP Host missing")
	}
	for _, bad := range []string{"evil.example\n.test", "https://game.example.test/path", "127.0.0.1", "bad..example.test"} {
		if cleanHostname(bad) != "" {
			t.Fatal("unsafe display name accepted")
		}
	}
	var collected bytes.Buffer
	reader := observedReader{Reader: bytes.NewReader(data), observe: func(b []byte) { collected.Write(b) }}
	forwarded, err := io.ReadAll(&reader)
	if err != nil || !bytes.Equal(data, forwarded) || !bytes.Equal(data, collected.Bytes()) {
		t.Fatal("inspection changed forwarded bytes")
	}
	o = clientNameObserver{found: func(string, string) { t.Fatal("oversized prefix accepted") }}
	o.observe(make([]byte, 65537))
	if !o.done || o.pending != nil {
		t.Fatal("prefix buffer unbounded")
	}
}

func TestTLSNameFromRealRelayedHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	e, s := console(t, localDial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, s, destination(server.Listener.Addr().(*net.TCPAddr).Port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// The certificate belongs to the local httptest server; production traffic is untouched.
	secure := tls.Client(c, &tls.Config{ServerName: "game.example.test", InsecureSkipVerify: true})
	if err := secure.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(secure, "GET / HTTP/1.1\r\nHost: game.example.test\r\nConnection: close\r\n\r\n")
	if _, err := io.ReadAll(secure); err != nil {
		t.Fatal(err)
	}
	rows := e.connectionReports()
	if len(rows) != 1 || rows[0].Domain != "game.example.test" || rows[0].DomainSource != "TLS SNI" {
		t.Fatalf("real connection name missing: %+v", rows)
	}
}

func TestDNSNameFromRealRelayedUDP(t *testing.T) {
	query, reply := dnsPair(t)
	host, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go func() {
		b := make([]byte, 2048)
		_, a, err := host.ReadFromUDP(b)
		if err == nil {
			host.WriteToUDP(reply, a)
		}
	}()
	e, s := console(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, host.LocalAddr().String())
	})
	dest := destination(53)
	c, err := gonet.DialUDP(s, nil, &dest, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	if _, err := c.Read(b); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for len(e.names.lookup("203.0.113.8", time.Now())) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if names := e.names.lookup("203.0.113.8", time.Now()); len(names) != 1 || names[0] != "game.example.test" {
		t.Fatalf("relayed DNS name missing: %v", names)
	}
}
