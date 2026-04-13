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
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: dynamic_forward_proxy
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      grpc_service:
                        envoy_grpc:
                          cluster_name: ext_authz
                  - name: envoy.filters.http.router
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
                      grpc_service:
                        envoy_grpc:
                          cluster_name: ext_authz
                  - name: envoy.filters.http.router
    - name: dns_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: %d
          protocol: UDP
      listener_filters:
        - name: envoy.filters.udp.dns_filter
  clusters:
    - name: ext_authz
      type: STATIC
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
      type: LOGICAL_DNS
      load_assignment:
        cluster_name: dynamic_forward_proxy
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 443
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
`, cfg.NodeID, cfg.ExplicitPort, cfg.TransparentPort, cfg.DNSPort, host, authzPort), nil
}
