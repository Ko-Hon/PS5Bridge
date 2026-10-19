package main

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Destination metadata only. No packet contents or persistent history.
type endpointReport struct {
	ID             string   `json:"id"`
	Protocol       string   `json:"protocol"`
	IP             string   `json:"ip"`
	Port           uint16   `json:"port"`
	Active         int      `json:"active"`
	ConnectLatency *float64 `json:"connectLatency,omitempty"`
	DialFailed     bool     `json:"dialFailed"`
	Updated        float64  `json:"updated"`
	Domain         string   `json:"domain,omitempty"`
	DomainSource   string   `json:"domainSource,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	Client         string   `json:"client,omitempty"`
}

func (r *endpointRegistry) setDomain(key, name, source string) {
	name = cleanHostname(name)
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.entries[key]; e != nil {
		if e.Domain != "" && e.Domain != name {
			aliases := append([]string(nil), e.Aliases...)
			if len(aliases) == 0 {
				aliases = append(aliases, e.Domain)
			}
			found := false
			for _, n := range aliases {
				if n == name {
					found = true
				}
			}
			if !found {
				aliases = append(aliases, name)
			}
			if len(aliases) > 4 {
				aliases = aliases[len(aliases)-4:]
			}
			e.Aliases = aliases
		}
		e.Domain = name
		e.DomainSource = source
	}
}

type endpointRegistry struct {
	mu      sync.Mutex
	entries map[string]*endpointReport
}

func (r *endpointRegistry) begin(protocol, address string) string {
	return r.beginFrom(protocol, address, "")
}
func (r *endpointRegistry) beginFrom(protocol, address, client string) string {
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	p, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || ipErr != nil || !ip.IsGlobalUnicast() || portErr != nil || p == 0 || (protocol != "TCP" && protocol != "UDP") {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*endpointReport)
	}
	r.prune(time.Now())
	key := protocol + "/" + address
	if client != "" {
		key = client + "/" + key
	}
	e := r.entries[key]
	if e == nil {
		e = &endpointReport{ID: key, Protocol: protocol, IP: ip.String(), Port: uint16(p), Client: client}
		r.entries[key] = e
	}
	e.Active++
	e.Updated = float64(time.Now().UnixMilli()) / 1000
	return key
}

func (r *endpointRegistry) dialResult(key string, elapsed time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.entries[key]; e != nil {
		e.DialFailed = err != nil
		e.ConnectLatency = nil
		// UDP connect only assigns a peer locally; it is never a round-trip measurement.
		if e.Protocol == "TCP" && err == nil {
			n := float64(elapsed.Microseconds()) / 1000
			e.ConnectLatency = &n
		}
		e.Updated = float64(time.Now().UnixMilli()) / 1000
	}
}

func (r *endpointRegistry) finish(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.entries[key]; e != nil {
		if e.Active > 0 {
			e.Active--
		}
		e.Updated = float64(time.Now().UnixMilli()) / 1000
	}
}

// Called under the lock. Active entries are bounded by the engine's 512 flow slots;
// keep at most 128 completed destinations and expire them after a minute.
func (r *endpointRegistry) prune(now time.Time) {
	var closed []*endpointReport
	for key, e := range r.entries {
		if e.Active != 0 {
			continue
		}
		if float64(now.UnixMilli())/1000-e.Updated > 60 {
			delete(r.entries, key)
		} else {
			closed = append(closed, e)
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].Updated > closed[j].Updated })
	for _, e := range closed[min(len(closed), 128):] {
		delete(r.entries, e.ID)
	}
}

func (r *endpointRegistry) snapshot() []endpointReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(time.Now())
	rows := make([]endpointReport, 0, len(r.entries))
	for _, e := range r.entries {
		row := *e
		row.Aliases = append([]string(nil), e.Aliases...)
		if e.ConnectLatency != nil {
			n := *e.ConnectLatency
			row.ConnectLatency = &n
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].Active > 0) != (rows[j].Active > 0) {
			return rows[i].Active > 0
		}
		if rows[i].Updated != rows[j].Updated {
			return rows[i].Updated > rows[j].Updated
		}
		return rows[i].ID < rows[j].ID
	})
	return rows[:min(len(rows), 12)]
}
