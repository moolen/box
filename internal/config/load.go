package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path, cwd string) (Config, error) {
	var cfg Config

	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return Config{}, fmt.Errorf("determine cwd: %w", err)
		}
	}

	configPath := path
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(cwd, configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", configPath, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", configPath, err)
	}

	if cfg.Sandbox.Workdir != "" && !filepath.IsAbs(cfg.Sandbox.Workdir) {
		cfg.Sandbox.Workdir = filepath.Join(cwd, cfg.Sandbox.Workdir)
	}

	// Transitional compatibility shims: keep the new YAML contract
	// (`network.envoy` + `network.policy`) while maintaining the old in-memory API.
	cfg.Network.TransparentProxy = TransparentProxyConfig{
		Enabled:  cfg.Network.Envoy.Enabled,
		Mode:     cfg.Network.Envoy.Mode,
		HTTPPort: cfg.Network.Envoy.HTTPPort,
		TLSPort:  cfg.Network.Envoy.TLSPort,
	}
	cfg.Policy = deriveLegacyPolicy(cfg.Network.Policy)

	return cfg, nil
}

func ValidateRuntime(cfg Config) error {
	mode := strings.TrimSpace(cfg.Network.Mode)
	if mode == "" {
		mode = "monitor"
	}
	if !strings.EqualFold(mode, "monitor") && !strings.EqualFold(mode, "enforce") {
		return fmt.Errorf("network.mode=%q is unsupported; allowed values are monitor and enforce", cfg.Network.Mode)
	}
	if strings.EqualFold(cfg.Network.Envoy.Mode, "mitm") || strings.EqualFold(cfg.Network.TransparentProxy.Mode, "mitm") {
		return errors.New("network.envoy.mode=mitm (aka network.transparent_proxy.mode=mitm) is not supported by runtime yet")
	}
	for i, rule := range cfg.Network.Policy {
		if err := validateNetworkPolicyRule(rule); err != nil {
			return fmt.Errorf("network.policy[%d]: %w", i, err)
		}
	}
	return nil
}

func deriveLegacyPolicy(rules []NetworkPolicyRule) PolicyConfig {
	var out PolicyConfig
	for _, rule := range rules {
		if h := strings.TrimSpace(rule.Hostname); h != "" {
			out.AllowDomains = append(out.AllowDomains, h)
		}
		if c := strings.TrimSpace(rule.CIDR); c != "" {
			out.ExtraAllowedCIDRs = append(out.ExtraAllowedCIDRs, c)
		}
		out.Egress = append(out.Egress, EgressRule{
			Hostname: strings.TrimSpace(rule.Hostname),
			CIDR:     strings.TrimSpace(rule.CIDR),
			Transport: []TransportRule{{
				Protocol: "tcp",
				Ports:    append([]int(nil), rule.Ports...),
			}},
		})
	}
	return out
}

func validateNetworkPolicyRule(rule NetworkPolicyRule) error {
	hasHostname := strings.TrimSpace(rule.Hostname) != ""
	hasCIDR := strings.TrimSpace(rule.CIDR) != ""
	if hasHostname == hasCIDR {
		return errors.New("must set exactly one of hostname or cidr")
	}
	if hasHostname {
		if err := validateHostnameSelector(rule.Hostname); err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
	}
	if hasCIDR {
		if _, err := netip.ParsePrefix(strings.TrimSpace(rule.CIDR)); err != nil {
			return fmt.Errorf("invalid cidr %q: %w", rule.CIDR, err)
		}
	}
	if len(rule.Ports) == 0 {
		return errors.New("must specify at least one port")
	}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}
	}
	if rule.HTTP != nil {
		if len(rule.HTTP.Path) == 0 {
			return errors.New("http.path must have at least one entry when http is set")
		}
		for _, p := range rule.HTTP.Path {
			p = strings.TrimSpace(p)
			if p == "" {
				return errors.New("http.path entries must be non-empty")
			}
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("http.path entry %q must start with /", p)
			}
			if _, err := path.Match(p, "/"); err != nil {
				return fmt.Errorf("http.path entry %q is not a valid glob: %w", p, err)
			}
		}
	}
	return nil
}

func validateHostnameSelector(hostname string) error {
	host := strings.TrimSpace(hostname)
	if host == "" {
		return errors.New("must be non-empty")
	}
	if strings.HasPrefix(host, "*.") {
		base := strings.TrimPrefix(host, "*.")
		if strings.Contains(base, "*") {
			return fmt.Errorf("invalid wildcard hostname %q", hostname)
		}
		if normalizeHostname(base) == "" {
			return fmt.Errorf("invalid wildcard hostname %q", hostname)
		}
		return nil
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("invalid wildcard hostname %q", hostname)
	}
	if normalizeHostname(host) == "" {
		return fmt.Errorf("invalid hostname %q", hostname)
	}
	return nil
}

func normalizeHostname(hostname string) string {
	host := strings.TrimSpace(hostname)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return ""
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return ""
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
	}
	return host
}
