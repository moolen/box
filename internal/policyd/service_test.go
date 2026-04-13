package policyd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"

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

func TestHandlerAuthorizeHTTPAllowsAbsoluteURLRequest(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{80},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/allowed/*"},
			},
		}},
	})

	req := httptest.NewRequest(http.MethodPost, "http://policyd.local/authorize/http", nil)
	req.Header.Set("Method", http.MethodGet)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Path", "http://example.com/allowed/value?x=1")
	req.Header.Set("X-Forwarded-Proto", "http")

	resp := httptest.NewRecorder()
	svc.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", resp.Code, http.StatusOK, resp.Body.String())
	}
}

func TestHandlerAuthorizeHTTPDeniesPathMismatch(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "http://policyd.local/authorize/http", nil)
	req.Header.Set("Method", http.MethodGet)
	req.Header.Set("Host", "example.com:443")
	req.Header.Set("Path", "https://example.com/blocked")
	req.Header.Set("X-Forwarded-Proto", "https")

	resp := httptest.NewRecorder()
	svc.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", resp.Code, http.StatusForbidden, resp.Body.String())
	}
}

func TestHandlerAuthorizeHTTPAcceptsOriginalRequestPathFallback(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{80},
		}},
	})

	req := httptest.NewRequest(http.MethodPost, "http://policyd.local/", nil)
	req.Header.Set("Method", http.MethodGet)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Path", "/")
	req.Header.Set("X-Forwarded-Proto", "http")

	resp := httptest.NewRecorder()
	svc.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", resp.Code, http.StatusOK, resp.Body.String())
	}
}

func TestHandlerAuthorizeHTTPAllowsCONNECTAuthorityRequest(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
		}},
	})

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Header.Set("X-Forwarded-Proto", "http")

	resp := httptest.NewRecorder()
	svc.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", resp.Code, http.StatusOK, resp.Body.String())
	}
}

func TestCheckGRPCAllowsCONNECTAuthorityRequest(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
		}},
	})

	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Destination: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "93.184.216.34",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: 443,
							},
						},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: http.MethodConnect,
					Host:   "example.com:443",
					Scheme: "http",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := codes.Code(resp.GetStatus().GetCode()); got != codes.OK {
		t.Fatalf("status = %v, want %v", got, codes.OK)
	}
	if resp.GetOkResponse() == nil {
		t.Fatalf("ok response = nil, want allow response")
	}
}

func TestCheckGRPCAllowsCONNECTWhenOnlyInnerHTTPSRequestShouldEnforcePath(t *testing.T) {
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

	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Destination: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "93.184.216.34",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: 443,
							},
						},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: http.MethodConnect,
					Host:   "example.com:443",
					Scheme: "http",
					Path:   "example.com:443",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := codes.Code(resp.GetStatus().GetCode()); got != codes.OK {
		t.Fatalf("status = %v, want %v; denied=%#v", got, codes.OK, resp.GetDeniedResponse())
	}
}

func TestCheckGRPCPrefersAuthorityPortOverProxyListenerPort(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
		}},
	})

	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Destination: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "127.0.0.1",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: 19001,
							},
						},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: http.MethodConnect,
					Host:   "example.com:443",
					Scheme: "http",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := codes.Code(resp.GetStatus().GetCode()); got != codes.OK {
		t.Fatalf("status = %v, want %v", got, codes.OK)
	}
}

func TestCheckGRPCUsesOriginalTargetHeadersForExplicitWebSocketCIDRRule(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			CIDR:  "203.0.113.7/32",
			Ports: []int{8443},
		}},
	})

	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Destination: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "127.0.0.1",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: 19001,
							},
						},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: http.MethodGet,
					Host:   "127.0.0.1:19001",
					Path:   "/chat",
					Headers: map[string]string{
						"x-box-original-target":    "ws://203.0.113.7:8443/chat",
						"x-box-original-authority": "203.0.113.7:8443",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := codes.Code(resp.GetStatus().GetCode()); got != codes.OK {
		t.Fatalf("status = %v, want %v; denied=%#v", got, codes.OK, resp.GetDeniedResponse())
	}
}

func TestCheckGRPCObserveAllowsTLSNetworkAuthzAndEmitsWouldBlockTLSVerdict(t *testing.T) {
	var events []Event
	svc := NewService(ServiceConfig{
		Mode: ModeObserve,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "allowed.example",
			Ports:    []int{443},
		}},
		OnEvent: func(event Event) {
			events = append(events, event)
		},
	})

	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Destination: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "93.184.216.34",
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: 443,
							},
						},
					},
				},
			},
			TlsSession: &authv3.AttributeContext_TLSSession{
				Sni: "example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := codes.Code(resp.GetStatus().GetCode()); got != codes.OK {
		t.Fatalf("status = %v, want %v", got, codes.OK)
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v, want 1 event", events)
	}
	if events[0].Type != "tls" {
		t.Fatalf("event type = %q, want tls", events[0].Type)
	}
	if events[0].Hostname != "example.com" {
		t.Fatalf("event hostname = %q, want example.com", events[0].Hostname)
	}
	if events[0].Verdict != VerdictWouldBlock {
		t.Fatalf("event verdict = %q, want would_block", events[0].Verdict)
	}
}

func TestStartServesDNSPolicyEvaluatedQueries(t *testing.T) {
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(upstream) error = %v", err)
	}
	defer upstreamConn.Close()

	upstream := &dns.Server{
		PacketConn: upstreamConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.ParseIP("93.184.216.34"),
			})
			if err := w.WriteMsg(reply); err != nil {
				t.Errorf("WriteMsg() error = %v", err)
			}
		}),
	}
	go func() {
		_ = upstream.ActivateAndServe()
	}()
	defer upstream.Shutdown()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(http) error = %v", err)
	}
	httpAddr := httpLn.Addr().String()
	if err := httpLn.Close(); err != nil {
		t.Fatalf("httpLn.Close() error = %v", err)
	}

	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(dns) error = %v", err)
	}
	dnsAddr := dnsConn.LocalAddr().String()
	if err := dnsConn.Close(); err != nil {
		t.Fatalf("dnsConn.Close() error = %v", err)
	}

	server, err := Start(context.Background(), httpAddr, dnsAddr, "", "", NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{53},
		}},
		DNSUpstream: []string{upstreamConn.LocalAddr().String()},
	}))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := server.Stop(); stopErr != nil {
			t.Fatalf("server.Stop() error = %v", stopErr)
		}
	}()

	client := &dns.Client{}

	allowedReq := new(dns.Msg)
	allowedReq.SetQuestion("example.com.", dns.TypeA)
	allowedResp, _, err := client.Exchange(allowedReq, dnsAddr)
	if err != nil {
		t.Fatalf("allowed Exchange() error = %v", err)
	}
	if allowedResp.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowed Rcode = %d, want success", allowedResp.Rcode)
	}
	if len(allowedResp.Answer) == 0 {
		t.Fatalf("allowed Answer = %#v, want forwarded record", allowedResp.Answer)
	}

	blockedReq := new(dns.Msg)
	blockedReq.SetQuestion("blocked.example.net.", dns.TypeA)
	blockedResp, _, err := client.Exchange(blockedReq, dnsAddr)
	if err != nil {
		t.Fatalf("blocked Exchange() error = %v", err)
	}
	if blockedResp.Rcode != dns.RcodeRefused {
		t.Fatalf("blocked Rcode = %d, want refused", blockedResp.Rcode)
	}
}
