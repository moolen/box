package monitor

import (
	"strings"
	"testing"
)

func TestCollectorAggregatesDNSHTTPAndTLS(t *testing.T) {
	collector := NewCollector()

	collector.AddDNS("Example.COM.", VerdictAllow)
	collector.AddDNS("example.com", VerdictAllow)
	collector.AddDNS("", VerdictDeny)
	collector.AddDNS("bad host", VerdictDeny)
	collector.AddTLS("api.Example.com.", VerdictAllow)
	collector.AddTLS("   ", VerdictDeny)
	collector.AddTLS("https://api.example.com", VerdictDeny)
	collector.AddHTTP("GET", "example.com", VerdictAllow)
	collector.AddHTTP("get", "example.com.", VerdictAllow)
	collector.AddHTTP("", "example.com", VerdictAllow)
	collector.AddHTTP("POST", "", VerdictDeny)
	collector.AddHTTP("PUT", "bad/host", VerdictDeny)

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
