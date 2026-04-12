package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
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
	for idx, rule := range cfg.Policy.Egress {
		if err := validateEgressRule(rule); err != nil {
			return fmt.Errorf("policy.egress[%d]: %w", idx, err)
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
	if hasHostname && NormalizeHostname(rule.Hostname) == "" {
		return errors.New("hostname is invalid")
	}
	if hasCIDR {
		if err := validateIPv4CIDR(rule.CIDR); err != nil {
			return err
		}
	}
	for i, transport := range rule.Transport {
		if err := validateTransportRule(transport); err != nil {
			return fmt.Errorf("transport[%d]: %w", i, err)
		}
	}
	for i, icmp := range rule.ICMP {
		if err := validateICMPRule(icmp); err != nil {
			return fmt.Errorf("icmp[%d]: %w", i, err)
		}
	}
	return nil
}

func validateTransportRule(rule TransportRule) error {
	protocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if protocol != "tcp" && protocol != "udp" {
		return errors.New("transport protocol must be tcp or udp")
	}
	if len(rule.Ports) == 0 {
		return errors.New("transport ports must be explicitly specified")
	}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return errors.New("transport port must be in range 1..65535")
		}
	}
	return nil
}

func validateICMPRule(rule ICMPRule) error {
	if rule.Type < 0 || rule.Type > 255 {
		return errors.New("icmp type must be in range 0..255")
	}
	if rule.Code < 0 || rule.Code > 255 {
		return errors.New("icmp code must be in range 0..255")
	}
	return nil
}

func validateIPv4CIDR(value string) error {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return errors.New("cidr must be valid ipv4 cidr")
	}
	if ip == nil || ip.To4() == nil {
		return errors.New("cidr must be valid ipv4 cidr")
	}
	return nil
}
