package policyd

import (
	"context"
	"net/netip"
	"strings"

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

func (s *Service) CheckHTTP(_ context.Context, req HTTPCheckRequest) (HTTPCheckResponse, error) {
	decision := Evaluate(Request{
		Protocol:        req.Protocol,
		DestinationIP:   req.DestinationIP,
		DestinationPort: req.DestinationPort,
		SNI:             req.SNI,
		Authority:       req.Authority,
		Path:            req.Path,
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

	s.emit(Event{
		Type:     "tcp",
		Protocol: string(req.Protocol),
		Hostname: strings.TrimSpace(req.Authority),
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
