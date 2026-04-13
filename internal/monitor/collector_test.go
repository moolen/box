package monitor

import (
	"strings"
	"testing"
)

func TestCollectorAggregatesDNSHTTPAndTLS(t *testing.T) {
	collector := NewCollector()

	collector.AddDNS("Example.COM.", VerdictAllow, "")
	collector.AddDNS("example.com", VerdictAllow, "")
	collector.AddDNS("", VerdictDeny, "dns_not_allowed")
	collector.AddDNS("bad host", VerdictDeny, "dns_not_allowed")
	collector.AddTLS("api.Example.com.", VerdictAllow, "")
	collector.AddTLS("   ", VerdictDeny, "unsupported_protocol")
	collector.AddTLS("https://api.example.com", VerdictDeny, "unsupported_protocol")
	collector.AddHTTP("GET", "example.com", VerdictAllow, "")
	collector.AddHTTP("get", "example.com.", VerdictAllow, "")
	collector.AddHTTP("", "example.com", VerdictAllow, "")
	collector.AddHTTP("POST", "", VerdictDeny, "invalid_host_signal")
	collector.AddHTTP("PUT", "bad/host", VerdictDeny, "invalid_host_signal")
	collector.AddICMP("198.51.100.7", 8, intPtr(0), VerdictWouldBlock, "no_matching_rule")
	collector.AddICMP("198.51.100.7", 8, intPtr(0), VerdictWouldBlock, "no_matching_rule")

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
	if got := snapshot.DNS[UnknownHostname]; got.Reason != "dns_not_allowed" {
		t.Fatalf("DNS[%q].Reason = %q, want %q", UnknownHostname, got.Reason, "dns_not_allowed")
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
	if got := snapshot.TLS[UnknownHostname]; got.Reason != "unsupported_protocol" {
		t.Fatalf("TLS[%q].Reason = %q, want %q", UnknownHostname, got.Reason, "unsupported_protocol")
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
	if got := snapshot.HTTP[HTTPKey{Method: "POST", Hostname: UnknownHostname}]; got.Reason != "invalid_host_signal" {
		t.Fatalf("HTTP[POST %q].Reason = %q, want %q", UnknownHostname, got.Reason, "invalid_host_signal")
	}
	if got := snapshot.HTTP[HTTPKey{Method: "PUT", Hostname: UnknownHostname}]; got.Count != 1 {
		t.Fatalf("HTTP[PUT %q].Count = %d, want 1", UnknownHostname, got.Count)
	}
	if got := snapshot.HTTP[HTTPKey{Method: "PUT", Hostname: UnknownHostname}]; got.Verdict != VerdictDeny {
		t.Fatalf("HTTP[PUT %q].Verdict = %q, want %q", UnknownHostname, got.Verdict, VerdictDeny)
	}

	if got := snapshot.ICMP[ICMPKey{Target: "198.51.100.7", Type: 8, Code: 0, HasCode: true}]; got.Count != 2 {
		t.Fatalf("ICMP[type=8 code=0 target=198.51.100.7].Count = %d, want 2", got.Count)
	}
	if got := snapshot.ICMP[ICMPKey{Target: "198.51.100.7", Type: 8, Code: 0, HasCode: true}]; got.Verdict != VerdictWouldBlock {
		t.Fatalf("ICMP[type=8 code=0 target=198.51.100.7].Verdict = %q, want %q", got.Verdict, VerdictWouldBlock)
	}
	if got := snapshot.ICMP[ICMPKey{Target: "198.51.100.7", Type: 8, Code: 0, HasCode: true}]; got.Reason != "no_matching_rule" {
		t.Fatalf("ICMP[type=8 code=0 target=198.51.100.7].Reason = %q, want %q", got.Reason, "no_matching_rule")
	}
}

func TestRenderSummaryFormatsSectionsAndCounts(t *testing.T) {
	summary := RenderSummary(Snapshot{
		DNS: map[string]Row{
			"example.com": {
				Count:   2,
				Verdict: VerdictWouldAllow,
			},
		},
		HTTP: map[HTTPKey]Row{
			{Method: "GET", Hostname: "example.com"}: {
				Count:   3,
				Verdict: VerdictWouldAllow,
			},
		},
		TLS: map[string]Row{
			UnknownHostname: {
				Count:   1,
				Verdict: VerdictWouldBlock,
				Reason:  "unsupported_protocol",
			},
		},
		ICMP: map[ICMPKey]Row{
			{Target: "198.51.100.7", Type: 8, Code: 0, HasCode: true}: {
				Count:   4,
				Verdict: VerdictWouldBlock,
				Reason:  "no_matching_rule",
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
	mustContain(t, summary, "(unsupported_protocol)")
	mustContain(t, summary, "ICMP")
	mustContain(t, summary, "TYPE 8 CODE 0 198.51.100.7")
	mustContain(t, summary, "(no_matching_rule)")
	mustContain(t, summary, "WOULD_ALLOW")
	mustContain(t, summary, "WOULD_BLOCK")
	mustContain(t, summary, "Total events: 10")

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
	if strings.Contains(dnsOnly, "ICMP") {
		t.Fatalf("RenderSummary() unexpectedly included ICMP section: %q", dnsOnly)
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

func intPtr(v int) *int {
	return &v
}
