package monitor

import (
	"net"
	"strconv"
	"strings"
	"unicode"

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

	if parsedHost, parsedPort, err := net.SplitHostPort(normalized); err == nil {
		port, portErr := strconv.Atoi(parsedPort)
		if portErr != nil || port < 0 || port > 65535 || parsedHost == "" {
			return ""
		}
		normalized = parsedHost
	}

	normalized = strings.ToLower(normalized)
	normalized = strings.TrimSuffix(normalized, ".")
	if !isValidHostname(normalized) {
		return ""
	}
	return normalized
}

func EvaluateHostname(policy config.PolicyConfig, hostname string) Verdict {
	host := NormalizeHostname(hostname)
	if host == "" {
		return VerdictDeny
	}

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

func isValidHostname(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
