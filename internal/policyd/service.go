package policyd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/miekg/dns"
	"google.golang.org/grpc"

	"gvisor-net/internal/config"
)

type Event struct {
	Type     string
	Protocol string
	Hostname string
	Method   string
	Path     string
	Host     string
	SNI      string
	Verdict  Verdict
	Reason   string
}

type ServiceConfig struct {
	Mode        Mode
	Rules       []config.NetworkPolicyRule
	DNSUpstream []string
	OnEvent     func(Event)
}

type Service struct {
	cfg ServiceConfig
}

type Server struct {
	grpcServer    *grpc.Server
	grpcListener  net.Listener
	dnsServer     *dns.Server
	dnsConn       net.PacketConn
	proxyListener net.Listener
	stopOnce      sync.Once
	stopErr       error
}

type HTTPCheckRequest struct {
	Protocol        Protocol
	DestinationIP   netip.Addr
	DestinationPort int
	SNI             string
	Authority       string
	Method          string
	Path            string
}

type HTTPCheckResponse struct {
	Allowed  bool
	Decision Decision
}

type TCPCheckRequest struct {
	Protocol        Protocol
	DestinationIP   netip.Addr
	DestinationPort int
	SNI             string
	Authority       string
}

type TCPCheckResponse struct {
	Allowed  bool
	Decision Decision
}

type DNSCheckRequest struct {
	Hostname string
}

type DNSCheckResponse struct {
	Allowed   bool
	Decision  Decision
	Upstreams []string
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg}
}

func Start(ctx context.Context, httpListenAddr string, dnsListenAddr string, proxyListenAddr string, proxyUpstreamAddr string, svc *Service) (*Server, error) {
	if svc == nil {
		return nil, errors.New("service is required")
	}
	grpcListener, err := net.Listen("tcp", strings.TrimSpace(httpListenAddr))
	if err != nil {
		return nil, err
	}
	dnsConn, err := net.ListenPacket("udp", strings.TrimSpace(dnsListenAddr))
	if err != nil {
		_ = grpcListener.Close()
		return nil, err
	}
	var proxyListener net.Listener
	if strings.TrimSpace(proxyListenAddr) != "" {
		proxyListener, err = net.Listen("tcp", strings.TrimSpace(proxyListenAddr))
		if err != nil {
			_ = dnsConn.Close()
			_ = grpcListener.Close()
			return nil, err
		}
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, svc)
	dnsServer := &dns.Server{
		PacketConn: dnsConn,
		Handler:    dns.HandlerFunc(svc.handleDNS),
	}
	runner := &Server{
		grpcServer:    grpcServer,
		grpcListener:  grpcListener,
		dnsServer:     dnsServer,
		dnsConn:       dnsConn,
		proxyListener: proxyListener,
	}

	go func() {
		<-ctx.Done()
		_ = runner.Stop()
	}()
	go func() {
		err := grpcServer.Serve(grpcListener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			_ = runner.Stop()
		}
	}()
	go func() {
		err := dnsServer.ActivateAndServe()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			_ = runner.Stop()
		}
	}()
	if proxyListener != nil {
		go runner.serveExplicitProxy(proxyUpstreamAddr)
	}

	return runner, nil
}

func (s *Server) Stop() error {
	if s == nil {
		return nil
	}

	s.stopOnce.Do(func() {
		var errs []error
		if s.grpcListener != nil {
			if err := s.grpcListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		if s.grpcServer != nil {
			s.grpcServer.Stop()
		}
		if s.dnsServer != nil {
			if err := s.dnsServer.Shutdown(); err != nil && !errors.Is(err, net.ErrClosed) && err.Error() != "dns: server not started" {
				errs = append(errs, err)
			}
		}
		if s.proxyListener != nil {
			if err := s.proxyListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		s.stopErr = errors.Join(errs...)
	})
	return s.stopErr
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize/http", s.handleAuthorizeHTTP)
	mux.HandleFunc("/", s.handleAuthorizeHTTP)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Envoy ext_authz forwards CONNECT checks with an authority-form request target
		// such as "example.com:443". net/http's ServeMux does not route those to "/".
		if r.Method == http.MethodConnect {
			s.handleAuthorizeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Service) CheckHTTP(_ context.Context, req HTTPCheckRequest) (HTTPCheckResponse, error) {
	decision := Evaluate(Request{
		Protocol:        req.Protocol,
		DestinationIP:   req.DestinationIP,
		DestinationPort: req.DestinationPort,
		SNI:             req.SNI,
		Authority:       req.Authority,
		Path:            req.Path,
		IsConnect:       strings.EqualFold(strings.TrimSpace(req.Method), http.MethodConnect),
	}, s.cfg.Rules, s.cfg.Mode)

	s.emit(Event{
		Type:     "http",
		Protocol: string(req.Protocol),
		Hostname: strings.TrimSpace(req.Authority),
		Method:   req.Method,
		Path:     req.Path,
		Host:     req.Authority,
		SNI:      req.SNI,
		Verdict:  decision.Verdict,
		Reason:   decision.Reason,
	})
	return HTTPCheckResponse{Allowed: allowedFromDecision(s.cfg.Mode, decision), Decision: decision}, nil
}

func (s *Service) CheckTCP(_ context.Context, req TCPCheckRequest) (TCPCheckResponse, error) {
	decision := finalize(s.cfg.Mode, Decision{
		Verdict: VerdictDeny,
		Reason:  "unsupported_protocol",
	})
	if req.Protocol == ProtocolHTTP || req.Protocol == ProtocolHTTPS {
		decision = Evaluate(Request{
			Protocol:        req.Protocol,
			DestinationIP:   req.DestinationIP,
			DestinationPort: req.DestinationPort,
			SNI:             req.SNI,
			Authority:       req.Authority,
		}, s.cfg.Rules, s.cfg.Mode)
	}

	eventType := "tcp"
	if req.Protocol == ProtocolHTTPS {
		eventType = "tls"
	}
	hostname := strings.TrimSpace(firstNonEmpty(req.SNI, req.Authority))

	s.emit(Event{
		Type:     eventType,
		Protocol: string(req.Protocol),
		Hostname: hostname,
		Host:     req.Authority,
		SNI:      req.SNI,
		Verdict:  decision.Verdict,
		Reason:   decision.Reason,
	})
	return TCPCheckResponse{Allowed: allowedFromDecision(s.cfg.Mode, decision), Decision: decision}, nil
}

func (s *Service) CheckDNS(_ context.Context, req DNSCheckRequest) (DNSCheckResponse, error) {
	decision := dnsDecision(strings.TrimSpace(req.Hostname), s.cfg.Rules, s.cfg.Mode)
	s.emit(Event{
		Type:     "dns",
		Protocol: "dns",
		Hostname: req.Hostname,
		Verdict:  decision.Verdict,
		Reason:   decision.Reason,
	})
	return DNSCheckResponse{
		Allowed:   allowedFromDecision(s.cfg.Mode, decision),
		Decision:  decision,
		Upstreams: append([]string(nil), s.cfg.DNSUpstream...),
	}, nil
}

func (s *Service) emit(event Event) {
	if s == nil || s.cfg.OnEvent == nil {
		return
	}
	s.cfg.OnEvent(event)
}

func (s *Service) handleAuthorizeHTTP(w http.ResponseWriter, r *http.Request) {
	checkReq, err := httpCheckRequestFromAuthz(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	resp, err := s.CheckHTTP(r.Context(), checkReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Policy-Verdict", string(resp.Decision.Verdict))
	if resp.Decision.Reason != "" {
		w.Header().Set("X-Policy-Reason", resp.Decision.Reason)
	}
	if resp.Allowed {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, resp.Decision.Reason, http.StatusForbidden)
}

func (s *Service) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	if len(req.Question) == 0 {
		reply.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(reply)
		return
	}

	for _, question := range req.Question {
		resp, err := s.CheckDNS(context.Background(), DNSCheckRequest{
			Hostname: strings.TrimSuffix(question.Name, "."),
		})
		if err != nil {
			reply.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(reply)
			return
		}
		if !resp.Allowed {
			reply.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(reply)
			return
		}
	}

	upstreamResp, err := exchangeDNSQuery(req, s.cfg.DNSUpstream)
	if err != nil {
		reply.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(reply)
		return
	}
	upstreamResp.Id = req.Id
	_ = w.WriteMsg(upstreamResp)
}

func httpCheckRequestFromAuthz(r *http.Request) (HTTPCheckRequest, error) {
	authority := firstNonEmpty(
		r.Header.Get("X-Box-Original-Authority"),
		connectAuthority(r),
		r.Header.Get("Host"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("Authority"),
	)
	rawPath := firstNonEmpty(
		r.Header.Get("X-Box-Original-Target"),
		r.Header.Get("Path"),
		r.Header.Get("X-Envoy-Original-Path"),
		"/",
	)
	protocol := inferHTTPProtocol(
		r.Header.Get("X-Forwarded-Proto"),
		rawPath,
		authority,
		r.Header.Get("X-Envoy-Original-Dst-Host"),
	)

	path, authorityFromPath, pathPort, pathIP := normalizeAuthzPath(rawPath)
	if strings.TrimSpace(authority) == "" {
		authority = authorityFromPath
	}

	dstIP, dstPort := parseOriginalDestination(r.Header.Get("X-Envoy-Original-Dst-Host"))
	if !dstIP.IsValid() || dstIP.IsLoopback() {
		dstIP = pathIP
	}

	_, authorityPort, authorityIP := parseAuthorityDestination(authority)
	if !dstIP.IsValid() || dstIP.IsLoopback() {
		dstIP = authorityIP
	}

	port := authorityPort
	if port == 0 {
		port = pathPort
	}
	if port == 0 {
		port = defaultPortForProtocol(protocol)
	}
	if port == 0 {
		port = dstPort
	}

	return HTTPCheckRequest{
		Protocol:        protocol,
		DestinationIP:   dstIP,
		DestinationPort: port,
		Authority:       authority,
		Method:          firstNonEmpty(r.Header.Get("Method"), r.Header.Get("X-Envoy-Original-Method")),
		Path:            path,
	}, nil
}

func inferHTTPProtocol(forwardedProto string, rawPath string, authority string, originalDst string) Protocol {
	switch strings.ToLower(strings.TrimSpace(forwardedProto)) {
	case string(ProtocolHTTPS):
		return ProtocolHTTPS
	case string(ProtocolHTTP):
		return ProtocolHTTP
	}

	if parsed, err := url.Parse(strings.TrimSpace(rawPath)); err == nil {
		switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
		case string(ProtocolHTTPS):
			return ProtocolHTTPS
		case string(ProtocolHTTP):
			return ProtocolHTTP
		case "wss":
			return ProtocolHTTPS
		case "ws":
			return ProtocolHTTP
		}
	}

	if _, port, _ := parseAuthorityDestination(authority); port == 443 {
		return ProtocolHTTPS
	}
	if _, port := parseOriginalDestination(originalDst); port == 443 {
		return ProtocolHTTPS
	}

	return ProtocolHTTP
}

func normalizeAuthzPath(rawPath string) (path string, authority string, port int, ip netip.Addr) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "/", "", 0, netip.Addr{}
	}

	parsed, err := url.Parse(trimmed)
	if err == nil && strings.TrimSpace(parsed.Scheme) != "" && strings.TrimSpace(parsed.Host) != "" {
		host, hostPort, hostIP := parseAuthorityDestination(parsed.Host)
		path = parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		return path, firstNonEmpty(parsed.Host, host), hostPort, hostIP
	}

	return trimmed, "", 0, netip.Addr{}
}

func parseOriginalDestination(value string) (netip.Addr, int) {
	host, port, ip := parseAuthorityDestination(value)
	if host == "" {
		return netip.Addr{}, 0
	}
	return ip, port
}

func parseAuthorityDestination(authority string) (host string, port int, ip netip.Addr) {
	trimmed := strings.TrimSpace(authority)
	if trimmed == "" {
		return "", 0, netip.Addr{}
	}

	host = trimmed
	if splitHost, splitPort, err := net.SplitHostPort(trimmed); err == nil {
		host = splitHost
		port, _ = strconv.Atoi(splitPort)
	}

	unbracketed := strings.Trim(host, "[]")
	if parsedIP, err := netip.ParseAddr(unbracketed); err == nil {
		ip = parsedIP
	}
	return host, port, ip
}

func defaultPortForProtocol(protocol Protocol) int {
	if protocol == ProtocolHTTPS {
		return 443
	}
	return 80
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func connectAuthority(r *http.Request) string {
	if r == nil || r.Method != http.MethodConnect {
		return ""
	}
	return strings.TrimSpace(r.Host)
}

func exchangeDNSQuery(req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	var lastErr error
	for _, upstream := range upstreams {
		resp, _, err := client.Exchange(req.Copy(), strings.TrimSpace(upstream))
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no dns upstreams configured")
	}
	return nil, lastErr
}

func allowedFromDecision(mode Mode, decision Decision) bool {
	if mode == ModeObserve {
		return true
	}
	return decision.Verdict == VerdictAllow
}

func dnsDecision(hostname string, rules []config.NetworkPolicyRule, mode Mode) Decision {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	for _, rule := range rules {
		ruleHost := strings.TrimSpace(rule.Hostname)
		if ruleHost == "" {
			continue
		}
		if matchHostnameRule(host, ruleHost) {
			return finalize(mode, Decision{
				Verdict: VerdictAllow,
				Reason:  "dns_allowed",
				Rule:    "host:" + strings.ToLower(strings.TrimSuffix(ruleHost, ".")),
			})
		}
	}
	return finalize(mode, Decision{
		Verdict: VerdictDeny,
		Reason:  "dns_not_allowed",
	})
}
