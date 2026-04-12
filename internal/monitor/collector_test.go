package monitor

import (
	"strings"
	"testing"

	"gvisor-net/internal/config"
)

func TestVerdictDenyWinsOverAllow(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{{
			Hostname: "example.com",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}},
	}

	got := EvaluateHostname(policy, "blocked.test")
	if got != VerdictDeny {
		t.Fatalf("EvaluateHostname() = %q, want %q for hostname outside allowlist", got, VerdictDeny)
	}

	got = EvaluateHostname(policy, "api.example.com")
	if got != VerdictAllow {
		t.Fatalf("EvaluateHostname() = %q, want %q", got, VerdictAllow)
	}

	got = EvaluateHostname(policy, "other.test")
	if got != VerdictDeny {
		t.Fatalf("EvaluateHostname() = %q, want %q when allow list is non-empty", got, VerdictDeny)
	}
}

func TestMalformedPolicyRulesDenyConservatively(t *testing.T) {
	tests := []struct {
		name   string
		policy config.PolicyConfig
		host   string
	}{
		{
			name: "malformed allow rule",
			policy: config.PolicyConfig{
				Egress: []config.EgressRule{{
					Hostname: "bad rule",
					Transport: []config.TransportRule{{
						Protocol: "tcp",
						Ports:    []int{443},
					}},
				}},
			},
			host: "example.com",
		},
		{
			name: "malformed deny rule",
			policy: config.PolicyConfig{
				Egress: []config.EgressRule{{
					Hostname: "https://blocked.example.com",
					Transport: []config.TransportRule{{
						Protocol: "tcp",
						Ports:    []int{443},
					}},
				}},
			},
			host: "example.com",
		},
		{
			name: "mixed valid and malformed rules",
			policy: config.PolicyConfig{
				Egress: []config.EgressRule{
					{
						Hostname: "example.com",
						Transport: []config.TransportRule{{
							Protocol: "tcp",
							Ports:    []int{443},
						}},
					},
					{
						Hostname: "bad/deny",
						Transport: []config.TransportRule{{
							Protocol: "tcp",
							Ports:    []int{443},
						}},
					},
				},
			},
			host: "example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateHostname(tc.policy, tc.host)
			if got != VerdictDeny {
				t.Fatalf("EvaluateHostname() = %q, want %q for conservative handling of malformed rules", got, VerdictDeny)
			}
		})
	}
}

func TestEvaluateHostnameDeniesWhenStructuredPolicyContainsInvalidHostnameRule(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{{
			Hostname: "https://bad.example.com",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}},
	}

	if got := EvaluateHostname(policy, "api.example.com"); got != VerdictDeny {
		t.Fatalf("EvaluateHostname() = %q, want %q for invalid hostname rule", got, VerdictDeny)
	}
}

func TestUnknownHostnameVerdictDefaultsToAllowWithoutAllowlist(t *testing.T) {
	policy := config.PolicyConfig{}

	got := EvaluateHostname(policy, "")
	if got != VerdictAllow {
		t.Fatalf("EvaluateHostname(empty) = %q, want %q with empty allowlist", got, VerdictAllow)
	}

	got = EvaluateHostname(policy, "bad host")
	if got != VerdictAllow {
		t.Fatalf("EvaluateHostname(malformed) = %q, want %q with empty allowlist", got, VerdictAllow)
	}
}

func TestUnknownHostnameVerdictDeniesWhenAllowlistPresent(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{{
			Hostname: "example.com",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}},
	}

	got := EvaluateHostname(policy, "")
	if got != VerdictDeny {
		t.Fatalf("EvaluateHostname(empty) = %q, want %q with non-empty allowlist", got, VerdictDeny)
	}

	got = EvaluateHostname(policy, "bad host")
	if got != VerdictDeny {
		t.Fatalf("EvaluateHostname(malformed) = %q, want %q with non-empty allowlist", got, VerdictDeny)
	}
}

func TestEvaluateHostnameUsesStructuredHostnameRules(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{
			{
				Hostname: "example.com",
				Transport: []config.TransportRule{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
			},
			{
				CIDR: "93.184.216.0/24",
				Transport: []config.TransportRule{{
					Protocol: "tcp",
					Ports:    []int{80},
				}},
			},
		},
	}

	if got := EvaluateHostname(policy, "api.example.com"); got != VerdictAllow {
		t.Fatalf("EvaluateHostname() = %q, want allow from structured hostname rule despite conflicting legacy fields", got)
	}
}

func TestEvaluateHostnameWithCIDROnlyPolicyDefaultsToAllow(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{{
			CIDR: "93.184.216.0/24",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}},
	}

	if got := EvaluateHostname(policy, "arbitrary.example.com"); got != VerdictAllow {
		t.Fatalf("EvaluateHostname() = %q, want %q when hostname allowlist is empty", got, VerdictAllow)
	}
}

func TestCollectorAggregatesDNSHTTPAndTLS(t *testing.T) {
	collector := NewCollector(config.PolicyConfig{
		Egress: []config.EgressRule{{
			Hostname: "example.com",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}},
	})

	collector.AddDNS("Example.COM.")
	collector.AddDNS("example.com")
	collector.AddDNS("")
	collector.AddDNS("bad host")
	collector.AddTLS("api.Example.com.")
	collector.AddTLS("   ")
	collector.AddTLS("https://api.example.com")
	collector.AddHTTP("GET", "example.com")
	collector.AddHTTP("get", "example.com.")
	collector.AddHTTP("", "example.com")
	collector.AddHTTP("POST", "")
	collector.AddHTTP("PUT", "bad/host")

	snapshot := collector.Snapshot()

	if got := snapshot.DNS["example.com"]; got.Count != 2 {
		t.Fatalf("DNS[example.com].Count = %d, want 2", got.Count)
	}
	if got := snapshot.DNS["example.com"]; got.Verdict != VerdictAllow {
		t.Fatalf("DNS[example.com].Verdict = %q, want %q", got.Verdict, VerdictAllow)
	}
	if got := snapshot.DNS[UnknownHostname]; got.Count != 2 {
		t.Fatalf("DNS[%q].Count = %d, want 2", UnknownHostname, got.Count)
	}
	if got := snapshot.DNS[UnknownHostname]; got.Verdict != VerdictDeny {
		t.Fatalf("DNS[%q].Verdict = %q, want %q", UnknownHostname, got.Verdict, VerdictDeny)
	}

	if got := snapshot.TLS["api.example.com"]; got.Count != 1 {
		t.Fatalf("TLS[api.example.com].Count = %d, want 1", got.Count)
	}
	if got := snapshot.TLS["api.example.com"]; got.Verdict != VerdictAllow {
		t.Fatalf("TLS[api.example.com].Verdict = %q, want %q", got.Verdict, VerdictAllow)
	}
	if got := snapshot.TLS[UnknownHostname]; got.Count != 2 {
		t.Fatalf("TLS[%q].Count = %d, want 2", UnknownHostname, got.Count)
	}
	if got := snapshot.TLS[UnknownHostname]; got.Verdict != VerdictDeny {
		t.Fatalf("TLS[%q].Verdict = %q, want %q", UnknownHostname, got.Verdict, VerdictDeny)
	}

	if got := snapshot.HTTP[HTTPKey{Method: "GET", Hostname: "example.com"}]; got.Count != 2 {
		t.Fatalf("HTTP[GET example.com].Count = %d, want 2", got.Count)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "GET", Hostname: "example.com"}]; got.Verdict != VerdictAllow {
		t.Fatalf("HTTP[GET example.com].Verdict = %q, want %q", got.Verdict, VerdictAllow)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "UNKNOWN", Hostname: "example.com"}]; got.Count != 1 {
		t.Fatalf("HTTP[UNKNOWN example.com].Count = %d, want 1", got.Count)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "UNKNOWN", Hostname: "example.com"}]; got.Verdict != VerdictAllow {
		t.Fatalf("HTTP[UNKNOWN example.com].Verdict = %q, want %q", got.Verdict, VerdictAllow)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "POST", Hostname: UnknownHostname}]; got.Count != 1 {
		t.Fatalf("HTTP[POST %q].Count = %d, want 1", UnknownHostname, got.Count)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "POST", Hostname: UnknownHostname}]; got.Verdict != VerdictDeny {
		t.Fatalf("HTTP[POST %q].Verdict = %q, want %q", UnknownHostname, got.Verdict, VerdictDeny)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "PUT", Hostname: UnknownHostname}]; got.Count != 1 {
		t.Fatalf("HTTP[PUT %q].Count = %d, want 1", UnknownHostname, got.Count)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "PUT", Hostname: UnknownHostname}]; got.Verdict != VerdictDeny {
		t.Fatalf("HTTP[PUT %q].Verdict = %q, want %q", UnknownHostname, got.Verdict, VerdictDeny)
	}
}

func TestRenderSummaryFormatsSectionsAndCounts(t *testing.T) {
	summary := RenderSummary(Snapshot{
		DNS: map[string]Row{
			"example.com": {
				Count:   2,
				Verdict: VerdictAllow,
			},
		},
		HTTP: map[HTTPKey]Row{
			{Method: "GET", Hostname: "example.com"}: {
				Count:   3,
				Verdict: VerdictAllow,
			},
		},
		TLS: map[string]Row{
			UnknownHostname: {
				Count:   1,
				Verdict: VerdictDeny,
			},
		},
	})

	mustContain(t, summary, "Monitor summary")
	mustContain(t, summary, "DNS")
	mustContain(t, summary, "example.com")
	mustContain(t, summary, "HTTP")
	mustContain(t, summary, "GET example.com")
	mustContain(t, summary, "TLS")
	mustContain(t, summary, UnknownHostname)
	mustContain(t, summary, "ALLOW")
	mustContain(t, summary, "DENY")
	mustContain(t, summary, "Total events: 6")

	dnsOnly := RenderSummary(Snapshot{
		DNS: map[string]Row{
			"only.example": {
				Count:   1,
				Verdict: VerdictAllow,
			},
		},
	})
	mustContain(t, dnsOnly, "DNS")
	if strings.Contains(dnsOnly, "HTTP") {
		t.Fatalf("RenderSummary() unexpectedly included HTTP section: %q", dnsOnly)
	}
	if strings.Contains(dnsOnly, "TLS") {
		t.Fatalf("RenderSummary() unexpectedly included TLS section: %q", dnsOnly)
	}
}

func TestRenderSummaryEmptySnapshotShowsNoTrafficMessage(t *testing.T) {
	summary := RenderSummary(Snapshot{})
	mustContain(t, summary, "Monitor summary")
	mustContain(t, summary, "no traffic captured")
	mustContain(t, summary, "Total events: 0")
}

func mustContain(t *testing.T, got string, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("string %q does not contain %q", got, want)
	}
}
