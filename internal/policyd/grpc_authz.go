package policyd

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

var _ authv3.AuthorizationServer = (*Service)(nil)

func (s *Service) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	if grpcHasHTTPAttributes(req) {
		checkReq, err := httpCheckRequestFromGRPC(req)
		if err != nil {
			return deniedCheckResponse(err.Error()), nil
		}

		resp, err := s.CheckHTTP(ctx, checkReq)
		if err != nil {
			return nil, err
		}
		if resp.Allowed {
			return allowedCheckResponse(), nil
		}
		return deniedCheckResponse(resp.Decision.Reason), nil
	}

	checkReq, err := tcpCheckRequestFromGRPC(req)
	if err != nil {
		return deniedCheckResponse(err.Error()), nil
	}

	resp, err := s.CheckTCP(ctx, checkReq)
	if err != nil {
		return nil, err
	}
	if resp.Allowed {
		return allowedCheckResponse(), nil
	}
	return deniedCheckResponse(resp.Decision.Reason), nil
}

func grpcHasHTTPAttributes(req *authv3.CheckRequest) bool {
	if req == nil {
		return false
	}
	attrs := req.GetAttributes()
	if attrs == nil || attrs.GetRequest() == nil {
		return false
	}
	return attrs.GetRequest().GetHttp() != nil
}

func httpCheckRequestFromGRPC(req *authv3.CheckRequest) (HTTPCheckRequest, error) {
	if req == nil {
		return HTTPCheckRequest{}, errors.New("missing check request")
	}
	attrs := req.GetAttributes()
	if attrs == nil {
		return HTTPCheckRequest{}, errors.New("missing request attributes")
	}
	httpReq := attrs.GetRequest().GetHttp()
	if httpReq == nil {
		return HTTPCheckRequest{}, errors.New("missing http attributes")
	}

	dstIP, dstPort := parseGRPCDestination(attrs.GetDestination())
	headers := httpReq.GetHeaders()
	authority := firstNonEmpty(
		grpcHeaderValue(headers, "x-box-original-authority"),
		strings.TrimSpace(httpReq.GetHost()),
		grpcHeaderValue(headers, ":authority"),
		grpcHeaderValue(headers, "host"),
		grpcHeaderValue(headers, "x-forwarded-host"),
	)
	rawPath := firstNonEmpty(
		grpcHeaderValue(headers, "x-box-original-target"),
		httpReq.GetPath(),
		"/",
	)
	protocol := inferGRPCProtocol(httpReq, authority, dstPort)

	path, authorityFromPath, pathPort, pathIP := normalizeAuthzPath(rawPath)
	if strings.TrimSpace(authority) == "" {
		authority = authorityFromPath
	}
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
		Method:          httpReq.GetMethod(),
		Path:            path,
	}, nil
}

func inferGRPCProtocol(httpReq *authv3.AttributeContext_HttpRequest, authority string, destinationPort int) Protocol {
	if httpReq == nil {
		return ProtocolHTTP
	}
	if strings.EqualFold(strings.TrimSpace(httpReq.GetMethod()), http.MethodConnect) {
		return ProtocolHTTPS
	}

	protocol := inferHTTPProtocol(httpReq.GetScheme(), httpReq.GetPath(), authority, "")
	if protocol == ProtocolHTTP && destinationPort == 443 {
		return ProtocolHTTPS
	}
	return protocol
}

func grpcHeaderValue(headers map[string]string, key string) string {
	if len(headers) == 0 || strings.TrimSpace(key) == "" {
		return ""
	}
	for headerKey, value := range headers {
		if strings.EqualFold(strings.TrimSpace(headerKey), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func tcpCheckRequestFromGRPC(req *authv3.CheckRequest) (TCPCheckRequest, error) {
	if req == nil {
		return TCPCheckRequest{}, errors.New("missing check request")
	}
	attrs := req.GetAttributes()
	if attrs == nil {
		return TCPCheckRequest{}, errors.New("missing request attributes")
	}

	dstIP, dstPort := parseGRPCDestination(attrs.GetDestination())
	if dstPort == 0 {
		dstPort = defaultPortForProtocol(ProtocolHTTPS)
	}
	sni := strings.TrimSpace(attrs.GetTlsSession().GetSni())
	return TCPCheckRequest{
		Protocol:        ProtocolHTTPS,
		DestinationIP:   dstIP,
		DestinationPort: dstPort,
		SNI:             sni,
		Authority:       sni,
	}, nil
}

func parseGRPCDestination(peer *authv3.AttributeContext_Peer) (netip.Addr, int) {
	socketAddress := peer.GetAddress().GetSocketAddress()
	if socketAddress == nil {
		return netip.Addr{}, 0
	}

	var ip netip.Addr
	if parsedIP, err := netip.ParseAddr(strings.TrimSpace(socketAddress.GetAddress())); err == nil {
		ip = parsedIP
	}
	return ip, int(socketAddress.GetPortValue())
}

func allowedCheckResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: grpcstatus.New(codes.OK, "").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

func deniedCheckResponse(reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: grpcstatus.New(codes.PermissionDenied, reason).Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Body: strings.TrimSpace(reason),
			},
		},
	}
}
