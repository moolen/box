package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
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
	if strings.EqualFold(cfg.Network.TransparentProxy.Mode, "mitm") {
		return errors.New("network.transparent_proxy.mode=mitm is not supported by runtime yet")
	}
	if cfg.Docker.Enabled {
		return errors.New("docker.enabled=true is unsupported; use buildkit instead")
	}
	for i, rule := range cfg.Policy.Egress {
		if err := validateEgressRule(rule); err != nil {
			return fmt.Errorf("policy.egress[%d]: %w", i, err)
		}
	}
	return nil
}

func validateEgressRule(rule EgressRule) error {
	hasHostname := strings.TrimSpace(rule.Hostname) != ""
	hasCIDR := strings.TrimSpace(rule.CIDR) != ""
	if hasHostname == hasCIDR {
		return errors.New("must set exactly one of hostname or cidr")
	}
	if len(rule.Transport) == 0 && len(rule.ICMP) == 0 {
		return errors.New("must allow at least one transport or icmp tuple")
	}
	if hasHostname {
		if normalizeHostname(rule.Hostname) == "" {
			return fmt.Errorf("invalid hostname %q", rule.Hostname)
		}
	}
	if hasCIDR {
		if _, err := netip.ParsePrefix(strings.TrimSpace(rule.CIDR)); err != nil {
			return fmt.Errorf("invalid cidr %q: %w", rule.CIDR, err)
		}
	}
	for _, transport := range rule.Transport {
		protocol := strings.ToLower(strings.TrimSpace(transport.Protocol))
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("unsupported transport protocol %q", transport.Protocol)
		}
		for _, port := range transport.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port %d", port)
			}
		}
	}
	for _, icmp := range rule.ICMP {
		if icmp.Type < 0 || icmp.Type > 255 || icmp.Code < 0 || icmp.Code > 255 {
			return fmt.Errorf("invalid icmp tuple type=%d code=%d", icmp.Type, icmp.Code)
		}
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
