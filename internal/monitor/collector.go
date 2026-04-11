package monitor

import (
	"strings"
	"sync"

	"gvisor-net/internal/config"
)

const UnknownHostname = "<unknown>"

type HTTPKey struct {
	Method   string
	Hostname string
}

type Row struct {
	Count   int
	Verdict Verdict
}

type Snapshot struct {
	DNS  map[string]Row
	HTTP map[HTTPKey]Row
	TLS  map[string]Row
}

type Collector struct {
	mu     sync.Mutex
	policy config.PolicyConfig
	dns    map[string]Row
	http   map[HTTPKey]Row
	tls    map[string]Row
}

func NewCollector(policy config.PolicyConfig) *Collector {
	return &Collector{
		policy: policy,
		dns:    make(map[string]Row),
		http:   make(map[HTTPKey]Row),
		tls:    make(map[string]Row),
	}
}

func (c *Collector) AddDNS(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := NormalizeHostname(hostname)
	display := toDisplayHostname(normalized)

	row := c.dns[display]
	row.Count++
	row.Verdict = EvaluateHostname(c.policy, normalized)
	c.dns[display] = row
}

func (c *Collector) AddTLS(hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := NormalizeHostname(hostname)
	display := toDisplayHostname(normalized)

	row := c.tls[display]
	row.Count++
	row.Verdict = EvaluateHostname(c.policy, normalized)
	c.tls[display] = row
}

func (c *Collector) AddHTTP(method string, hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	normalized := NormalizeHostname(hostname)
	key := HTTPKey{
		Method:   normalizeMethod(method),
		Hostname: toDisplayHostname(normalized),
	}

	row := c.http[key]
	row.Count++
	row.Verdict = EvaluateHostname(c.policy, normalized)
	c.http[key] = row
}

func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := Snapshot{
		DNS:  make(map[string]Row, len(c.dns)),
		HTTP: make(map[HTTPKey]Row, len(c.http)),
		TLS:  make(map[string]Row, len(c.tls)),
	}

	for host, row := range c.dns {
		snapshot.DNS[host] = row
	}
	for key, row := range c.http {
		snapshot.HTTP[key] = row
	}
	for host, row := range c.tls {
		snapshot.TLS[host] = row
	}

	return snapshot
}

func toDisplayHostname(normalized string) string {
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
