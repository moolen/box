package policyd

import (
	"net/http"
	"strings"
)

const (
	headerOriginalTarget     = "X-Box-Original-Target"
	headerOriginalAuthority  = "X-Box-Original-Authority"
	headerTrustedMetadata    = "X-Box-Trusted-Metadata"
	trustedExplicitWebsocket = "explicit-proxy-websocket-v1"
)

func hasTrustedOriginalMetadataHTTP(headers http.Header) bool {
	if len(headers) == 0 {
		return false
	}
	return strings.EqualFold(
		strings.TrimSpace(headers.Get(headerTrustedMetadata)),
		trustedExplicitWebsocket,
	)
}

func hasTrustedOriginalMetadataGRPC(headers map[string]string) bool {
	return strings.EqualFold(
		strings.TrimSpace(grpcHeaderValue(headers, headerTrustedMetadata)),
		trustedExplicitWebsocket,
	)
}
