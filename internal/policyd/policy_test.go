package policyd

import (
	"net/netip"
	"testing"

	"gvisor-net/internal/config"
)

func TestEvaluateHTTPSHostnamePathRule(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443, 8443},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/api/*"},
		},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 8443,
		SNI:             "example.com",
		Authority:       "example.com",
		Path:            "/api/v1",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %q, want allow (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateHostnameWildcardRule(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "*.example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "api.example.com",
		Authority:       "api.example.com",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %q, want allow (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateCIDRRuleMatchesDestinationIPAndPort(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		CIDR:  "203.0.113.0/24",
		Ports: []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationIP:   netip.MustParseAddr("203.0.113.7"),
		DestinationPort: 443,
		// Host signals intentionally inconsistent; CIDR rules should ignore them.
		SNI:       "example.com",
		Authority: "evil.example",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %q, want allow (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateICMPOnlyCIDRRuleDoesNotAllowHTTPS(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		CIDR: "203.0.113.0/24",
		ICMP: []config.ICMPPolicyRule{{
			Type: 8,
		}},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationIP:   netip.MustParseAddr("203.0.113.7"),
		DestinationPort: 443,
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want deny (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateICMPCIDRRuleMatchesTypeAndCode(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		CIDR: "203.0.113.0/24",
		ICMP: []config.ICMPPolicyRule{{
			Type: 8,
			Code: intPtr(0),
		}},
	}}

	decision := EvaluateICMP(netip.MustParseAddr("203.0.113.7"), 8, 0, rules, ModeObserve)

	if decision.Verdict != VerdictWouldAllow {
		t.Fatalf("Verdict = %q, want would_allow (decision = %#v)", decision.Verdict, decision)
	}
	if decision.Reason != "cidr_match" {
		t.Fatalf("Reason = %q, want cidr_match", decision.Reason)
	}
}

func TestEvaluateICMPCIDRRuleRejectsMismatchedCode(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		CIDR: "203.0.113.0/24",
		ICMP: []config.ICMPPolicyRule{{
			Type: 8,
			Code: intPtr(0),
		}},
	}}

	decision := EvaluateICMP(netip.MustParseAddr("203.0.113.7"), 8, 3, rules, ModeObserve)

	if decision.Verdict != VerdictWouldBlock {
		t.Fatalf("Verdict = %q, want would_block (decision = %#v)", decision.Verdict, decision)
	}
	if decision.Reason != "no_matching_rule" {
		t.Fatalf("Reason = %q, want no_matching_rule", decision.Reason)
	}
}

func intPtr(v int) *int {
	return &v
}

func TestEvaluateLiteralIPDoesNotMatchHostnameRule(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "allowed.example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationIP:   netip.MustParseAddr("203.0.113.7"),
		DestinationPort: 443,
		LiteralIP:       true,
		SNI:             "allowed.example.com",
		Authority:       "allowed.example.com",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want deny (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluatePortMismatchDenies(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 8443,
		SNI:             "example.com",
		Authority:       "example.com",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want deny (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateHostnameSignalMismatchDenies(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "evil.example",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want deny (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateModeObserveUsesWouldVerdicts(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	allowDecision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "example.com",
	}, rules, ModeObserve)
	if allowDecision.Verdict != VerdictWouldAllow {
		t.Fatalf("Verdict = %q, want would_allow (decision = %#v)", allowDecision.Verdict, allowDecision)
	}

	blockDecision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "not-example.com",
		Authority:       "not-example.com",
	}, rules, ModeObserve)
	if blockDecision.Verdict != VerdictWouldBlock {
		t.Fatalf("Verdict = %q, want would_block (decision = %#v)", blockDecision.Verdict, blockDecision)
	}
}

func TestEvaluateMalformedAuthorityFailsClosed(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "example.com:bad",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want deny (decision = %#v)", decision.Verdict, decision)
	}
}

func TestEvaluateAuthorityWithPortNormalizesAndAllows(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "example.com:443",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %q, want allow (decision = %#v)", decision.Verdict, decision)
	}
}
