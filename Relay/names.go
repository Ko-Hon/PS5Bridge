package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func cleanHostname(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return name
}

// The cache contains only names observed on this console's relayed connections.
// No reverse-DNS guesses, external lookups, or persistent browsing history.
type nameCache struct {
	mu      sync.Mutex
	entries map[string]map[string]time.Time
}

func (c *nameCache) put(ip, name string, ttl uint32, now time.Time) {
	name = cleanHostname(name)
	if name == "" || ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]map[string]time.Time)
	}
	if len(c.entries) >= 1024 {
		oldestIP := ""
		oldest := now.Add(2 * time.Hour)
		for addr, names := range c.entries {
			for n, expiry := range names {
				if !expiry.After(now) {
					delete(names, n)
				}
			}
			if len(names) == 0 {
				delete(c.entries, addr)
				continue
			}
			for _, expiry := range names {
				if expiry.Before(oldest) {
					oldestIP, oldest = addr, expiry
				}
			}
		}
		if c.entries[ip] == nil && len(c.entries) >= 1024 {
			delete(c.entries, oldestIP)
		}
	}
	names := c.entries[ip]
	if names == nil {
		names = make(map[string]time.Time)
		c.entries[ip] = names
	}
	if _, exists := names[name]; !exists && len(names) >= 4 {
		oldestName := ""
		oldest := now.Add(2 * time.Hour)
		for n, expiry := range names {
			if expiry.Before(oldest) {
				oldestName, oldest = n, expiry
			}
		}
		delete(names, oldestName)
	}
	names[name] = now.Add(time.Duration(min(ttl, 3600)) * time.Second)
}

func (c *nameCache) lookup(ip string, now time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []string
	for name, expiry := range c.entries[ip] {
		if expiry.After(now) {
			result = append(result, name)
		} else {
			delete(c.entries[ip], name)
		}
	}
	sort.Strings(result)
	return result
}

type dnsQuestion struct {
	name string
	kind dnsmessage.Type
	at   time.Time
}
type dnsObserver struct {
	mu      sync.Mutex
	pending map[uint16]dnsQuestion
	cache   *nameCache
}

func (d *dnsObserver) query(b []byte) {
	if len(b) > 65535 {
		return
	}
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || h.Response {
		return
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Class != dnsmessage.ClassINET {
		return
	}
	name := cleanHostname(qs[0].Name.String())
	if name == "" {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = make(map[uint16]dnsQuestion)
	}
	for id, q := range d.pending {
		if now.Sub(q.at) > 30*time.Second {
			delete(d.pending, id)
		}
	}
	if len(d.pending) >= 64 {
		for id := range d.pending {
			delete(d.pending, id)
			break
		}
	}
	d.pending[h.ID] = dnsQuestion{name, qs[0].Type, now}
}

func (d *dnsObserver) reply(b []byte) {
	if len(b) > 65535 {
		return
	}
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.Truncated || h.RCode != dnsmessage.RCodeSuccess {
		return
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Class != dnsmessage.ClassINET {
		return
	}
	d.mu.Lock()
	q, found := d.pending[h.ID]
	if !found || q.name != cleanHostname(qs[0].Name.String()) || q.kind != qs[0].Type || time.Since(q.at) > 30*time.Second {
		d.mu.Unlock()
		return
	}
	delete(d.pending, h.ID)
	d.mu.Unlock()
	answers, err := p.AllAnswers()
	if err != nil || len(answers) > 128 {
		return
	}
	// Follow only the queried name's CNAME chain, excluding unrelated A records.
	owner := q.name
	chainTTL := uint32(3600)
	for depth := 0; depth < 16; depth++ {
		next := ""
		for _, a := range answers {
			if a.Header.Class != dnsmessage.ClassINET || cleanHostname(a.Header.Name.String()) != owner {
				continue
			}
			switch body := a.Body.(type) {
			case *dnsmessage.AResource:
				d.cache.put(netip.AddrFrom4(body.A).String(), q.name, min(chainTTL, a.Header.TTL), time.Now())
			case *dnsmessage.AAAAResource:
				d.cache.put(netip.AddrFrom16(body.AAAA).String(), q.name, min(chainTTL, a.Header.TTL), time.Now())
			case *dnsmessage.CNAMEResource:
				next = cleanHostname(body.CNAME.String())
				chainTTL = min(chainTTL, a.Header.TTL)
			}
		}
		if next == "" || next == owner {
			break
		}
		owner = next
	}
}

type dnsStream struct {
	pending []byte
	feed    func([]byte)
	stopped bool
}

func (d *dnsStream) observe(b []byte) {
	if d.stopped {
		return
	}
	if len(d.pending)+len(b) > 131074 {
		d.pending = nil
		d.stopped = true
		return
	}
	d.pending = append(d.pending, b...)
	for len(d.pending) >= 2 {
		n := int(binary.BigEndian.Uint16(d.pending))
		if n < 12 {
			d.pending = nil
			d.stopped = true
			return
		}
		if len(d.pending) < n+2 {
			return
		}
		d.feed(d.pending[2 : n+2])
		d.pending = d.pending[n+2:]
	}
}

type observedReader struct {
	io.Reader
	observe func([]byte)
}

func (r *observedReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 {
		r.observe(b[:n])
	}
	return n, err
}

// Only the initial clear-text TLS ClientHello or HTTP headers are inspected.
// Encrypted payload is never decrypted, saved, or changed.
type clientNameObserver struct {
	pending []byte
	done    bool
	found   func(string, string)
}

func (o *clientNameObserver) observe(b []byte) {
	if o.done {
		return
	}
	if len(o.pending)+len(b) > 65536 {
		o.done = true
		o.pending = nil
		return
	}
	o.pending = append(o.pending, b...)
	name, source, done := clientName(o.pending)
	if done {
		o.done = true
		o.pending = nil
		if name != "" {
			o.found(name, source)
		}
	}
}

func clientName(b []byte) (name, source string, done bool) {
	if len(b) == 0 {
		return "", "", false
	}
	if b[0] != 22 {
		// Only HTTP request headers; arbitrary binary protocols are rejected early.
		prefix := string(b[:min(len(b), 8)])
		possible := false
		for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "} {
			if strings.HasPrefix(method, prefix) || strings.HasPrefix(prefix, method) {
				possible = true
				break
			}
		}
		if !possible {
			return "", "", true
		}
		end := bytes.Index(b, []byte("\r\n\r\n"))
		if end < 0 {
			return "", "", len(b) >= 16384
		}
		for _, line := range strings.Split(string(b[:end]), "\r\n")[1:] {
			key, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(key, "Host") {
				host := strings.TrimSpace(value)
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				return cleanHostname(host), "HTTP Host", true
			}
		}
		return "", "", true
	}
	var handshake []byte
	for offset := 0; offset < len(b); {
		if len(b)-offset < 5 {
			return "", "", false
		}
		if b[offset] != 22 || b[offset+1] != 3 {
			return "", "", true
		}
		n := int(binary.BigEndian.Uint16(b[offset+3 : offset+5]))
		if n == 0 || n > 18432 {
			return "", "", true
		}
		if len(b)-offset-5 < n {
			return "", "", false
		}
		handshake = append(handshake, b[offset+5:offset+5+n]...)
		offset += 5 + n
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return "", "", true
		}
		size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if size > 65532 {
			return "", "", true
		}
		if len(handshake) >= size+4 {
			return helloName(handshake[4 : size+4]), "TLS SNI", true
		}
	}
	return "", "", false
}

type nameCursor struct{ b []byte }

func (c *nameCursor) take(n int) []byte {
	if n < 0 || n > len(c.b) {
		c.b = nil
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}
func (c *nameCursor) vector(width int) []byte {
	b := c.take(width)
	if b == nil {
		return nil
	}
	n := int(b[0])
	if width == 2 {
		n = int(binary.BigEndian.Uint16(b))
	}
	return c.take(n)
}
func helloName(b []byte) string {
	c := nameCursor{b}
	if c.take(34) == nil || c.vector(1) == nil || c.vector(2) == nil || c.vector(1) == nil {
		return ""
	}
	ext := nameCursor{c.vector(2)}
	for len(ext.b) >= 4 {
		kind := binary.BigEndian.Uint16(ext.take(2))
		value := ext.vector(2)
		if value == nil {
			return ""
		}
		if kind != 0 {
			continue
		}
		names := nameCursor{value}
		list := nameCursor{names.vector(2)}
		for len(list.b) >= 3 {
			kind := list.take(1)[0]
			host := list.vector(2)
			if host == nil {
				return ""
			}
			if kind == 0 {
				return cleanHostname(string(host))
			}
		}
	}
	return ""
}

func (e *engine) connectionReports() []endpointReport {
	rows := e.endpoints.snapshot()
	for i := range rows {
		if rows[i].Domain != "" {
			continue
		}
		if names := e.names.lookup(rows[i].IP, time.Now()); len(names) > 0 {
			rows[i].Domain = names[0]
			rows[i].Aliases = names
			rows[i].DomainSource = "DNS 关联"
		}
	}
	return rows
}
