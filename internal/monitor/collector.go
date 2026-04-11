package monitor

import (
	"strings"
	"sync"
)

const UnknownHostname = "<unknown>"

type HTTPKey struct {
	Method   string
	Hostname string
}

type Snapshot struct {
	DNS  map[string]int
	HTTP map[HTTPKey]int
	TLS  map[string]int
}

type Collector struct {
	mu   sync.Mutex
	dns  map[string]int
	http map[HTTPKey]int
	tls  map[string]int
}

func NewCollector() *Collector {
	return &Collector{
		dns:  make(map[string]int),
		http: make(map[HTTPKey]int),
		tls:  make(map[string]int),
	}
}

func (c *Collector) AddDNS(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dns[normalizeDisplayHostname(hostname)]++
}

func (c *Collector) AddTLS(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tls[normalizeDisplayHostname(hostname)]++
}

func (c *Collector) AddHTTP(method string, hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := HTTPKey{
		Method:   normalizeMethod(method),
		Hostname: normalizeDisplayHostname(hostname),
	}
	c.http[key]++
}

func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := Snapshot{
		DNS:  make(map[string]int, len(c.dns)),
		HTTP: make(map[HTTPKey]int, len(c.http)),
		TLS:  make(map[string]int, len(c.tls)),
	}

	for host, count := range c.dns {
		snapshot.DNS[host] = count
	}
	for key, count := range c.http {
		snapshot.HTTP[key] = count
	}
	for host, count := range c.tls {
		snapshot.TLS[host] = count
	}

	return snapshot
}

func normalizeDisplayHostname(hostname string) string {
	normalized := NormalizeHostname(hostname)
	if normalized == "" {
		return UnknownHostname
	}
	return normalized
}

func normalizeMethod(method string) string {
	normalized := strings.TrimSpace(method)
	if normalized == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(normalized)
}
