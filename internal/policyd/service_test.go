package policyd

import (
	"context"
	"net/netip"
	"testing"

	"gvisor-net/internal/config"
)

func TestCheckHTTPReturnsDeniedForPathMismatch(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/allowed/*"},
			},
		}},
	})

	resp, err := svc.CheckHTTP(context.Background(), HTTPCheckRequest{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "example.com",
		Method:          "GET",
		Path:            "/blocked",
	})
	if err != nil {
		t.Fatalf("CheckHTTP() error = %v", err)
	}
	if resp.Allowed {
		t.Fatalf("Allowed = true, want false")
	}
}

func TestCheckTCPObserveAllowsButReportsUnsupportedProtocol(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode:  ModeObserve,
		Rules: nil,
	})

	resp, err := svc.CheckTCP(context.Background(), TCPCheckRequest{
		DestinationIP:   netip.MustParseAddr("203.0.113.7"),
		DestinationPort: 8443,
	})
	if err != nil {
		t.Fatalf("CheckTCP() error = %v", err)
	}
	if !resp.Allowed {
		t.Fatal("Allowed = false, want true in observe mode")
	}
	if resp.Decision.Verdict != VerdictWouldBlock {
		t.Fatalf("Verdict = %q, want would_block", resp.Decision.Verdict)
	}
}

func TestCheckDNSAllowsMatchingHostnameRule(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "*.example.com",
			Ports:    []int{443},
		}},
		DNSUpstream: []string{"1.1.1.1:53"},
	})

	resp, err := svc.CheckDNS(context.Background(), DNSCheckRequest{Hostname: "api.example.com"})
	if err != nil {
		t.Fatalf("CheckDNS() error = %v", err)
	}
	if !resp.Allowed {
		t.Fatal("Allowed = false, want true")
	}
	if len(resp.Upstreams) != 1 || resp.Upstreams[0] != "1.1.1.1:53" {
		t.Fatalf("Upstreams = %#v, want configured upstreams", resp.Upstreams)
	}
}

func TestCheckHTTPEmitsMonitorVerdictEvent(t *testing.T) {
	var events []Event
	svc := NewService(ServiceConfig{
		Mode: ModeObserve,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
		}},
		OnEvent: func(event Event) {
			events = append(events, event)
		},
	})

	_, err := svc.CheckHTTP(context.Background(), HTTPCheckRequest{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 443,
		SNI:             "example.com",
		Authority:       "example.com",
		Method:          "GET",
		Path:            "/",
	})
	if err != nil {
		t.Fatalf("CheckHTTP() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v, want 1 event", events)
	}
	if events[0].Verdict != VerdictWouldAllow {
		t.Fatalf("event verdict = %q, want would_allow", events[0].Verdict)
	}
}
