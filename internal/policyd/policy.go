package policyd

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"gvisor-net/internal/config"
)

type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeObserve Mode = "observe"
)

type Verdict string

const (
	VerdictAllow      Verdict = "allow"
	VerdictDeny       Verdict = "deny"
	VerdictWouldAllow Verdict = "would_allow"
	VerdictWouldBlock Verdict = "would_block"
)

type Request struct {
	Protocol Protocol

	DestinationIP   netip.Addr
	DestinationPort int
	LiteralIP       bool

	// Host signals for hostname rules.
	SNI       string
	Authority string

	// HTTP-layer fields (when available).
	Path      string
	IsConnect bool
}

type Decision struct {
	Verdict Verdict
	Reason  string
	Rule    string
}

func Evaluate(req Request, rules []config.NetworkPolicyRule, mode Mode) Decision {
	// CIDR rules match strictly on destination IP+port and do not use host signals.
	for _, rule := range rules {
		if strings.TrimSpace(rule.CIDR) == "" {
			continue
		}
		if !portMatches(rule.Ports, req.DestinationPort) {
			continue
		}
		pfx, err := netip.ParsePrefix(strings.TrimSpace(rule.CIDR))
		if err != nil || !req.DestinationIP.IsValid() || !pfx.Contains(req.DestinationIP) {
			continue
		}
		return finalize(mode, Decision{
			Verdict: VerdictAllow,
			Reason:  "cidr_match",
			Rule:    "cidr:" + strings.TrimSpace(rule.CIDR),
		})
	}
	if req.LiteralIP {
		return finalize(mode, Decision{
			Verdict: VerdictDeny,
			Reason:  "literal_ip_requires_cidr",
		})
	}

	// Hostname rules require consistent host signals when multiple are present.
	// If a host signal is present but malformed, fail closed.
	sni, sniPresent, sniOK := parseHostSignal(req.SNI)
	auth, authPresent, authOK := parseAuthority(req.Authority)
	if (sniPresent && !sniOK) || (authPresent && !authOK) {
		return finalize(mode, Decision{
			Verdict: VerdictDeny,
			Reason:  "invalid_host_signal",
		})
	}
	if sni != "" && auth != "" && sni != auth {
		return finalize(mode, Decision{
			Verdict: VerdictDeny,
			Reason:  "host_signal_mismatch",
			Rule:    "sni:" + sni + " authority:" + auth,
		})
	}

	host := sni
	if host == "" {
		host = auth
	}

	for _, rule := range rules {
		ruleHost := strings.TrimSpace(rule.Hostname)
		if ruleHost == "" {
			continue
		}
		if !portMatches(rule.Ports, req.DestinationPort) {
			continue
		}
		if !matchHostnameRule(host, ruleHost) {
			continue
		}
		if !req.IsConnect && rule.HTTP != nil && len(rule.HTTP.Path) > 0 {
			if !matchesAnyGlob(req.Path, rule.HTTP.Path) {
				continue
			}
		}
		return finalize(mode, Decision{
			Verdict: VerdictAllow,
			Reason:  "hostname_match",
			Rule:    "host:" + strings.ToLower(strings.TrimSuffix(ruleHost, ".")),
		})
	}

	return finalize(mode, Decision{
		Verdict: VerdictDeny,
		Reason:  "no_matching_rule",
	})
}

func finalize(mode Mode, d Decision) Decision {
	switch mode {
	case ModeObserve:
		if d.Verdict == VerdictAllow {
			d.Verdict = VerdictWouldAllow
		} else if d.Verdict == VerdictDeny {
			d.Verdict = VerdictWouldBlock
		}
	default:
		// ModeEnforce (and unknown modes) keep allow/deny.
	}
	return d
}

func portMatches(ports []int, dst int) bool {
	if len(ports) == 0 {
		return false
	}
	for _, p := range ports {
		if p == dst {
			return true
		}
	}
	return false
}

func parseHostSignal(in string) (host string, present bool, ok bool) {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return "", false, true
	}
	trimmed = strings.ToLower(strings.TrimSuffix(trimmed, "."))
	if trimmed == "" {
		return "", true, false
	}
	return trimmed, true, true
}

func parseAuthority(in string) (host string, present bool, ok bool) {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return "", false, true
	}

	// Common form: "host:port" or "[ipv6]:port". net.SplitHostPort handles both.
	if h, p, err := net.SplitHostPort(trimmed); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil || port < 0 || port > 65535 || h == "" {
			return "", true, false
		}
		host = strings.ToLower(strings.TrimSuffix(h, "."))
		if host == "" {
			return "", true, false
		}
		return host, true, true
	}

	// Fail closed if it looks like an attempt at host:port but didn't parse.
	// This avoids an attacker using malformed Authority to bypass the consistency check.
	if strings.Contains(trimmed, ":") {
		return "", true, false
	}

	host = strings.ToLower(strings.TrimSuffix(trimmed, "."))
	if host == "" {
		return "", true, false
	}
	return host, true, true
}

func matchHostnameRule(host string, rule string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	rule = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule), "."))
	if host == "" || rule == "" {
		return false
	}
	if host == rule {
		return true
	}

	// Common wildcard form: "*.example.com"
	if strings.HasPrefix(rule, "*.") && strings.Count(rule, "*") == 1 {
		suffix := strings.TrimPrefix(rule, "*.")
		if suffix == "" {
			return false
		}
		// Requires at least one label in front.
		return strings.HasSuffix(host, "."+suffix) && host != suffix
	}
	return false
}

func matchesAnyGlob(s string, patterns []string) bool {
	for _, p := range patterns {
		if matchGlob(p, s) {
			return true
		}
	}
	return false
}

// matchGlob implements a minimal glob where '*' matches any substring (including '/').
func matchGlob(pattern, s string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return s == pattern
	}

	parts := strings.Split(pattern, "*")
	// Prefix
	if parts[0] != "" && !strings.HasPrefix(s, parts[0]) {
		return false
	}
	// Suffix
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(s, last) {
		return false
	}

	// Middle parts
	i := 0
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[i:], part)
		if idx < 0 {
			return false
		}
		i += idx + len(part)
	}
	return true
}
