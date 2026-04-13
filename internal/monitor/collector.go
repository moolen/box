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

type ICMPKey struct {
	Target  string
	Type    int
	Code    int
	HasCode bool
}

type Row struct {
	Count   int
	Verdict Verdict
	Reason  string
}

type Snapshot struct {
	Total int
	DNS   map[string]Row
	HTTP  map[HTTPKey]Row
	TLS   map[string]Row
	ICMP  map[ICMPKey]Row
}

type Collector struct {
	mu    sync.Mutex
	dns   map[string]Row
	http  map[HTTPKey]Row
	tls   map[string]Row
	icmp  map[ICMPKey]Row
	total int
}

func NewCollector() *Collector {
	return &Collector{
		dns:  make(map[string]Row),
		http: make(map[HTTPKey]Row),
		tls:  make(map[string]Row),
		icmp: make(map[ICMPKey]Row),
	}
}

func (c *Collector) AddDNS(hostname string, verdict Verdict, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := NormalizeHostname(hostname)
	display := toDisplayHostname(normalized)

	row := c.dns[display]
	row.Count++
	row.Verdict = normalizeVerdict(verdict)
	row.Reason = normalizeReason(reason, verdict)
	c.dns[display] = row
	c.total++
}

func (c *Collector) AddTLS(hostname string, verdict Verdict, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := NormalizeHostname(hostname)
	display := toDisplayHostname(normalized)

	row := c.tls[display]
	row.Count++
	row.Verdict = normalizeVerdict(verdict)
	row.Reason = normalizeReason(reason, verdict)
	c.tls[display] = row
	c.total++
}

func (c *Collector) AddHTTP(method string, hostname string, verdict Verdict, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	normalized := NormalizeHostname(hostname)
	key := HTTPKey{
		Method:   normalizeMethod(method),
		Hostname: toDisplayHostname(normalized),
	}

	row := c.http[key]
	row.Count++
	row.Verdict = normalizeVerdict(verdict)
	row.Reason = normalizeReason(reason, verdict)
	c.http[key] = row
	c.total++
}

func (c *Collector) AddICMP(target string, icmpType int, icmpCode *int, verdict Verdict, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	normalized := NormalizeHostname(target)
	key := ICMPKey{
		Target: toDisplayHostname(normalized),
		Type:   icmpType,
	}
	if icmpCode != nil {
		key.Code = *icmpCode
		key.HasCode = true
	}

	row := c.icmp[key]
	row.Count++
	row.Verdict = normalizeVerdict(verdict)
	row.Reason = normalizeReason(reason, verdict)
	c.icmp[key] = row
	c.total++
}

func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := Snapshot{
		Total: c.total,
		DNS:   make(map[string]Row, len(c.dns)),
		HTTP:  make(map[HTTPKey]Row, len(c.http)),
		TLS:   make(map[string]Row, len(c.tls)),
		ICMP:  make(map[ICMPKey]Row, len(c.icmp)),
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
	for key, row := range c.icmp {
		snapshot.ICMP[key] = row
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

func normalizeReason(reason string, verdict Verdict) string {
	if !isDeniedVerdict(verdict) {
		return ""
	}
	return strings.TrimSpace(reason)
}

func normalizeVerdict(verdict Verdict) Verdict {
	switch verdict {
	case VerdictAllow:
		return VerdictAllow
	case VerdictDeny:
		return VerdictDeny
	case VerdictWouldAllow:
		return VerdictWouldAllow
	case VerdictWouldBlock:
		return VerdictWouldBlock
	default:
		return VerdictDeny
	}
}

func isDeniedVerdict(verdict Verdict) bool {
	switch normalizeVerdict(verdict) {
	case VerdictDeny, VerdictWouldBlock:
		return true
	default:
		return false
	}
}
