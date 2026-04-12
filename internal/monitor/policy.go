package monitor

import (
	"strings"

	"gvisor-net/internal/config"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

type Policy struct {
	allow   []string
	invalid bool
}

func NormalizeHostname(hostname string) string {
	return config.NormalizeHostname(hostname)
}

func EvaluateHostname(policy config.PolicyConfig, hostname string) Verdict {
	return CompilePolicy(policy).Evaluate(hostname)
}

func CompilePolicy(policy config.PolicyConfig) Policy {
	compiled := Policy{}
	compiled.allow, compiled.invalid = hostnamePolicyRules(policy)
	return compiled
}

func (p Policy) Evaluate(hostname string) Verdict {
	host := NormalizeHostname(hostname)
	return p.EvaluateNormalized(host)
}

func (p Policy) EvaluateNormalized(host string) Verdict {
	if p.invalid {
		return VerdictDeny
	}
	if host == "" {
		if len(p.allow) > 0 {
			return VerdictDeny
		}
		return VerdictAllow
	}
	if len(p.allow) > 0 && !matchesAny(host, p.allow) {
		return VerdictDeny
	}
	return VerdictAllow
}

func hostnamePolicyRules(policy config.PolicyConfig) (allow []string, invalid bool) {
	allow = make([]string, 0, len(policy.Egress))
	for _, rule := range policy.Egress {
		trimmed := strings.TrimSpace(rule.Hostname)
		if trimmed == "" {
			continue
		}
		normalized := NormalizeHostname(trimmed)
		if normalized == "" {
			invalid = true
			continue
		}
		allow = append(allow, normalized)
	}
	return allow, invalid
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
