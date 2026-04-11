package monitor

import (
	"strings"
	"testing"

	"gvisor-net/internal/config"
)

func TestVerdictDenyWinsOverAllow(t *testing.T) {
	policy := config.PolicyConfig{
		AllowDomains: []string{"example.com"},
		DenyDomains:  []string{"blocked.example.com"},
	}

	got := EvaluateHostname(policy, "blocked.example.com")
	if got != VerdictDeny {
		t.Fatalf("EvaluateHostname() = %q, want %q", got, VerdictDeny)
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

func TestCollectorAggregatesDNSHTTPAndTLS(t *testing.T) {
	collector := NewCollector()

	collector.AddDNS("Example.COM.")
	collector.AddDNS("example.com")
	collector.AddDNS("")
	collector.AddTLS("api.Example.com.")
	collector.AddTLS("   ")
	collector.AddHTTP("GET", "example.com")
	collector.AddHTTP("get", "example.com.")
	collector.AddHTTP("", "example.com")
	collector.AddHTTP("POST", "")

	snapshot := collector.Snapshot()

	if got := snapshot.DNS["example.com"]; got != 2 {
		t.Fatalf("DNS[example.com] = %d, want 2", got)
	}
	if got := snapshot.DNS[UnknownHostname]; got != 1 {
		t.Fatalf("DNS[%q] = %d, want 1", UnknownHostname, got)
	}

	if got := snapshot.TLS["api.example.com"]; got != 1 {
		t.Fatalf("TLS[api.example.com] = %d, want 1", got)
	}
	if got := snapshot.TLS[UnknownHostname]; got != 1 {
		t.Fatalf("TLS[%q] = %d, want 1", UnknownHostname, got)
	}

	if got := snapshot.HTTP[HTTPKey{Method: "GET", Hostname: "example.com"}]; got != 2 {
		t.Fatalf("HTTP[GET example.com] = %d, want 2", got)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "UNKNOWN", Hostname: "example.com"}]; got != 1 {
		t.Fatalf("HTTP[UNKNOWN example.com] = %d, want 1", got)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "POST", Hostname: UnknownHostname}]; got != 1 {
		t.Fatalf("HTTP[POST %q] = %d, want 1", UnknownHostname, got)
	}
}

func TestRenderSummaryFormatsSectionsAndCounts(t *testing.T) {
	summary := RenderSummary(Snapshot{
		DNS: map[string]int{
			"example.com": 2,
		},
		HTTP: map[HTTPKey]int{
			{Method: "GET", Hostname: "example.com"}: 3,
		},
		TLS: map[string]int{
			UnknownHostname: 1,
		},
	})

	mustContain(t, summary, "Monitor summary")
	mustContain(t, summary, "DNS")
	mustContain(t, summary, "example.com")
	mustContain(t, summary, "HTTP")
	mustContain(t, summary, "GET example.com")
	mustContain(t, summary, "TLS")
	mustContain(t, summary, UnknownHostname)
	mustContain(t, summary, "Total events: 6")

	dnsOnly := RenderSummary(Snapshot{
		DNS: map[string]int{
			"only.example": 1,
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

func mustContain(t *testing.T, got string, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("string %q does not contain %q", got, want)
	}
}
