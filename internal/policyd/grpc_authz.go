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
	authority := firstNonEmpty(
		strings.TrimSpace(httpReq.GetHost()),
		httpReq.GetHeaders()[":authority"],
		httpReq.GetHeaders()["host"],
		httpReq.GetHeaders()["x-forwarded-host"],
	)
	rawPath := firstNonEmpty(httpReq.GetPath(), "/")
	protocol := inferGRPCProtocol(httpReq, authority, dstPort)

	path, authorityFromPath, pathPort, pathIP := normalizeAuthzPath(rawPath)
	if strings.TrimSpace(authority) == "" {
		authority = authorityFromPath
	}
	if !dstIP.IsValid() {
		dstIP = pathIP
	}

	_, authorityPort, authorityIP := parseAuthorityDestination(authority)
	if !dstIP.IsValid() {
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
