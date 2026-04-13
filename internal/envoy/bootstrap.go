package envoy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type BootstrapConfig struct {
	NodeID                     string
	ExplicitPort               int
	TransparentPort            int
	DNSPort                    int
	DNSUpstream                []string
	AuthzAddress               string
	TransparentTLSCertificates []TLSCertificate
	UpstreamTrustBundlePath    string
}

type TLSCertificate struct {
	ServerNames []string
	CertPath    string
	KeyPath     string
}

func RenderBootstrap(cfg BootstrapConfig) (string, error) {
	if strings.TrimSpace(cfg.NodeID) == "" {
		return "", fmt.Errorf("node id is required")
	}
	if cfg.ExplicitPort <= 0 || cfg.TransparentPort <= 0 || cfg.DNSPort <= 0 {
		return "", fmt.Errorf("listener ports must be positive")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.AuthzAddress))
	if err != nil {
		return "", fmt.Errorf("parse authz address %q: %w", cfg.AuthzAddress, err)
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("authz host is required")
	}
	authzPort, err := strconv.Atoi(port)
	if err != nil || authzPort <= 0 {
		return "", fmt.Errorf("invalid authz port %q", port)
	}
	dnsResolvers, err := renderDNSResolvers(cfg.DNSUpstream)
	if err != nil {
		return "", err
	}
	transparentFilterChains, err := renderTransparentFilterChains(cfg.TransparentTLSCertificates)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`node:
  id: %s
static_resources:
  listeners:
    - name: explicit_proxy
      address:
        socket_address:
          address: 0.0.0.0
          port_value: %d
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: explicit_proxy
                route_config:
                  name: explicit_proxy_routes
                  virtual_hosts:
                    - name: explicit_proxy
                      domains: ["*", "*:*"]
                      routes:
                        - match:
                            connect_matcher: {}
                          route:
                            cluster: explicit_connect_mitm
                            upgrade_configs:
                              - upgrade_type: CONNECT
                                connect_config: {}
                        - match: { prefix: "/" }
                          route:
                            cluster: dynamic_forward_proxy
                upgrade_configs:
                  - upgrade_type: CONNECT
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: V3
                      grpc_service:
                        envoy_grpc:
                          cluster_name: ext_authz
                        timeout: 0.25s
                  - name: envoy.filters.http.dynamic_forward_proxy
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
                      dns_cache_config:
                        name: dynamic_forward_proxy_cache
                        dns_lookup_family: V4_ONLY
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: transparent_proxy
      address:
        socket_address:
          address: 0.0.0.0
          port_value: %d
      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
      filter_chains:
%s
    - name: dns_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: %d
          protocol: UDP
      listener_filters:
        - name: envoy.filters.udp.dns_filter
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.udp.dns_filter.v3.DnsFilterConfig
            stat_prefix: dns_listener
            client_config:
              max_pending_lookups: 1024
              dns_resolution_config:
                resolvers:
%s
            server_config:
              inline_dns_table:
                virtual_domains: []
  clusters:
    - name: ext_authz
      type: STATIC
      http2_protocol_options: {}
      load_assignment:
        cluster_name: ext_authz
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: %s
                      port_value: %d
    - name: dynamic_forward_proxy
      connect_timeout: 5s
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
          dns_cache_config:
            name: dynamic_forward_proxy_cache
            dns_lookup_family: V4_ONLY
    - name: explicit_connect_mitm
      type: STATIC
      connect_timeout: 5s
      load_assignment:
        cluster_name: explicit_connect_mitm
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: %d
    - name: dynamic_forward_proxy_tls
      connect_timeout: 5s
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
          dns_cache_config:
            name: dynamic_forward_proxy_cache
            dns_lookup_family: V4_ONLY
%s
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
`, cfg.NodeID, cfg.ExplicitPort, cfg.TransparentPort, transparentFilterChains, cfg.DNSPort, dnsResolvers, host, authzPort, cfg.TransparentPort, renderUpstreamTLSClusterTransportSocket(cfg.UpstreamTrustBundlePath)), nil
}

func renderTransparentFilterChains(certs []TLSCertificate) (string, error) {
	lines := make([]string, 0, len(certs)*24+24)
	for _, cert := range certs {
		if len(cert.ServerNames) == 0 {
			return "", fmt.Errorf("transparent tls certificate requires at least one server name")
		}
		if strings.TrimSpace(cert.CertPath) == "" || strings.TrimSpace(cert.KeyPath) == "" {
			return "", fmt.Errorf("transparent tls certificate requires cert and key paths")
		}
		lines = append(lines,
			"        - filter_chain_match:",
			"            transport_protocol: tls",
			"            server_names:",
		)
		for _, serverName := range cert.ServerNames {
			lines = append(lines, "              - "+serverName)
		}
		lines = append(lines,
			"          transport_socket:",
			"            name: envoy.transport_sockets.tls",
			"            typed_config:",
			"              \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
			"              common_tls_context:",
			"                tls_certificates:",
			"                  - certificate_chain:",
			"                      filename: "+cert.CertPath,
			"                    private_key:",
			"                      filename: "+cert.KeyPath,
			"          filters:",
		)
		lines = append(lines, renderTransparentHCMFilterChain("transparent_proxy_tls", "dynamic_forward_proxy_tls")...)
	}
	lines = append(lines,
		"        - filters:",
	)
	lines = append(lines, renderTransparentHCMFilterChain("transparent_proxy", "dynamic_forward_proxy")...)
	return strings.Join(lines, "\n"), nil
}

func renderTransparentHCMFilterChain(statPrefix, cluster string) []string {
	return []string{
		"            - name: envoy.filters.network.http_connection_manager",
		"              typed_config:",
		"                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
		"                stat_prefix: " + statPrefix,
		"                route_config:",
		"                  name: " + statPrefix + "_routes",
		"                  virtual_hosts:",
		"                    - name: " + statPrefix,
		"                      domains: [\"*\"]",
		"                      routes:",
		"                        - match: { prefix: \"/\" }",
		"                          route:",
		"                            cluster: " + cluster,
		"                http_filters:",
		"                  - name: envoy.filters.http.ext_authz",
		"                    typed_config:",
		"                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
		"                      transport_api_version: V3",
		"                      grpc_service:",
		"                        envoy_grpc:",
		"                          cluster_name: ext_authz",
		"                        timeout: 0.25s",
		"                  - name: envoy.filters.http.dynamic_forward_proxy",
		"                    typed_config:",
		"                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
		"                      dns_cache_config:",
		"                        name: dynamic_forward_proxy_cache",
		"                        dns_lookup_family: V4_ONLY",
		"                  - name: envoy.filters.http.router",
		"                    typed_config:",
		"                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
	}
}

func renderUpstreamTLSClusterTransportSocket(trustBundlePath string) string {
	if strings.TrimSpace(trustBundlePath) == "" {
		return `      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          auto_host_sni: true`
	}
	return fmt.Sprintf(`      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          auto_host_sni: true
          auto_sni_san_validation: true
          common_tls_context:
            validation_context:
              trusted_ca:
                filename: %s`, trustBundlePath)
}

func renderDNSResolvers(upstreams []string) (string, error) {
	if len(upstreams) == 0 {
		return "", fmt.Errorf("at least one dns upstream is required")
	}

	lines := make([]string, 0, len(upstreams)*4)
	for _, upstream := range upstreams {
		host, port, err := net.SplitHostPort(strings.TrimSpace(upstream))
		if err != nil {
			return "", fmt.Errorf("parse dns upstream %q: %w", upstream, err)
		}
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("dns upstream host is required")
		}
		portValue, err := strconv.Atoi(port)
		if err != nil || portValue <= 0 {
			return "", fmt.Errorf("invalid dns upstream port %q", port)
		}
		lines = append(lines,
			"                  - socket_address:",
			"                      address: "+host,
			"                      port_value: "+strconv.Itoa(portValue),
		)
	}
	return strings.Join(lines, "\n"), nil
}
