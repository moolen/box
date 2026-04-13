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

