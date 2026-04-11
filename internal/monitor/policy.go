package monitor

import (
	"net"
	"strings"

	"gvisor-net/internal/config"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

func NormalizeHostname(hostname string) string {
	normalized := strings.TrimSpace(hostname)
	if normalized == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(normalized); err == nil {
		normalized = parsedHost
	}

	normalized = strings.ToLower(normalized)
	normalized = strings.TrimSuffix(normalized, ".")
	return normalized
}

func EvaluateHostname(policy config.PolicyConfig, hostname string) Verdict {
	host := NormalizeHostname(hostname)

	allowRules := normalizeRules(policy.AllowDomains)
	denyRules := normalizeRules(policy.DenyDomains)

	if matchesAny(host, denyRules) {
		return VerdictDeny
	}

	if len(allowRules) > 0 && !matchesAny(host, allowRules) {
		return VerdictDeny
	}

	return VerdictAllow
}

func normalizeRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		normalized := NormalizeHostname(rule)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func matchesAny(host string, rules []string) bool {
	for _, rule := range rules {
		if matchHostnameRule(host, rule) {
			return true
		}
	}
	return false
}

func matchHostnameRule(host string, rule string) bool {
	if host == "" || rule == "" {
		return false
	}
	if host == rule {
		return true
	}
	return strings.HasSuffix(host, "."+rule)
}
