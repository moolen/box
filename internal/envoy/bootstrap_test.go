package envoy

import (
	"strings"
	"testing"
)

func TestRenderBootstrapIncludesExplicitTransparentAndDNSListeners(t *testing.T) {
	cfg := BootstrapConfig{
		NodeID:          "runtime-a",
		ExplicitPort:    19001,
		TransparentPort: 19002,
		DNSPort:         19053,
		DNSUpstream:     []string{"1.1.1.1:53", "8.8.8.8:53"},
		AuthzAddress:    "127.0.0.1:20001",
		TransparentTLSCertificates: []TLSCertificate{
			{
				ServerNames: []string{"example.com"},
				CertPath:    "/run/box/runtime-a/envoy/example.com.crt",
				KeyPath:     "/run/box/runtime-a/envoy/example.com.key",
			},
			{
				ServerNames: []string{"*.example.org"},
				CertPath:    "/run/box/runtime-a/envoy/wildcard-example.org.crt",
				KeyPath:     "/run/box/runtime-a/envoy/wildcard-example.org.key",
			},
		},
		UpstreamTrustBundlePath: "/run/box/runtime-a/ca/upstream-trust-bundle.crt",
	}

	content, err := RenderBootstrap(cfg)
	if err != nil {
		t.Fatalf("RenderBootstrap() error = %v", err)
	}

	for _, want := range []string{
		"19001",
		"19002",
		"19053",
		"ext_authz",
		"dynamic_forward_proxy",
		"grpc_service",
		"envoy_grpc",
		"cluster_name: ext_authz",
		"transport_api_version: V3",
		"http2_protocol_options: {}",
		"upgrade_configs",
		"upgrade_type: CONNECT",
		"connect_config: {}",
		"envoy.filters.http.dynamic_forward_proxy",
		"envoy.filters.listener.tls_inspector",
		"transport_protocol: tls",
		"server_names:",
		"example.com",
		"*.example.org",
		"DownstreamTlsContext",
		"/run/box/runtime-a/envoy/example.com.crt",
		"/run/box/runtime-a/envoy/example.com.key",
		"dynamic_forward_proxy_tls",
		"UpstreamTlsContext",
		"/run/box/runtime-a/ca/upstream-trust-bundle.crt",
		"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
		"dns_cache_config",
		"type.googleapis.com/envoy.extensions.filters.udp.dns_filter.v3.DnsFilterConfig",
		"inline_dns_table",
		"1.1.1.1",
		"8.8.8.8",
		"max_pending_lookups",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("bootstrap missing %q\ncontent=%s", want, content)
		}
	}
	if strings.Contains(content, "http_service:") {
		t.Fatalf("bootstrap unexpectedly still uses http ext_authz\ncontent=%s", content)
	}
	if strings.Contains(content, "resolution_timeout") {
		t.Fatalf("bootstrap unexpectedly includes unsupported dns client_config.resolution_timeout\ncontent=%s", content)
	}
}

func TestRenderBootstrapRejectsInvalidAuthzAddress(t *testing.T) {
	_, err := RenderBootstrap(BootstrapConfig{
		NodeID:          "runtime-a",
		ExplicitPort:    19001,
		TransparentPort: 19002,
		DNSPort:         19053,
		AuthzAddress:    "missing-port",
	})
	if err == nil {
		t.Fatal("RenderBootstrap() error = nil, want invalid authz address rejection")
	}
}
