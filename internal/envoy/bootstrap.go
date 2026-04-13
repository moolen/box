package envoy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type BootstrapConfig struct {
	NodeID          string
	ExplicitPort    int
	TransparentPort int
	DNSPort         int
	DNSUpstream     []string
	AuthzAddress    string
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
                            cluster: dynamic_forward_proxy
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
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: transparent_proxy
                route_config:
                  name: transparent_proxy_routes
                  virtual_hosts:
                    - name: transparent_proxy
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: dynamic_forward_proxy
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
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
`, cfg.NodeID, cfg.ExplicitPort, cfg.TransparentPort, cfg.DNSPort, dnsResolvers, host, authzPort), nil
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
