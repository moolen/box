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
	cfg := Config{
		Sandbox: SandboxConfig{
			WorkdirOverlay: true,
		},
		Network: NetworkConfig{
			Mode: "monitor",
		},
	}

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
	cfg.Mounts.StagedRO = resolveStagedMountSources(cfg.Mounts.StagedRO, cwd)
	cfg.Mounts.StagedRW = resolveStagedMountSources(cfg.Mounts.StagedRW, cwd)
	if mode := strings.TrimSpace(cfg.Network.Mode); mode != "" {
		cfg.Network.Mode = mode
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
	for i, rule := range cfg.Network.Policy {
		if err := validateNetworkPolicyRule(rule); err != nil {
			return fmt.Errorf("network.policy[%d]: %w", i, err)
		}
	}
	for i, mount := range cfg.Mounts.StagedRO {
		if err := validateStagedFileMount(mount); err != nil {
			return fmt.Errorf("mounts.staged_ro[%d]: %w", i, err)
		}
	}
	for i, mount := range cfg.Mounts.StagedRW {
		if err := validateStagedFileMount(mount); err != nil {
			return fmt.Errorf("mounts.staged_rw[%d]: %w", i, err)
		}
	}
	return nil
}

func resolveStagedMountSources(mounts []StagedFileMount, cwd string) []StagedFileMount {
	if len(mounts) == 0 {
		return nil
	}
	resolved := append([]StagedFileMount(nil), mounts...)
	for i := range resolved {
		resolved[i].Source = resolveHostPath(resolved[i].Source, cwd)
	}
	return resolved
}

func resolveHostPath(value, cwd string) string {
	pathValue := strings.TrimSpace(value)
	if pathValue == "" {
		return ""
	}
	if pathValue == "~" || strings.HasPrefix(pathValue, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if pathValue == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(pathValue, "~/"))
		}
	}
	if filepath.IsAbs(pathValue) {
		return pathValue
	}
	if cwd == "" {
		return pathValue
	}
	return filepath.Join(cwd, pathValue)
}

func validateStagedFileMount(mount StagedFileMount) error {
	if strings.TrimSpace(mount.Source) == "" {
		return errors.New("source is required")
	}
	target := strings.TrimSpace(mount.Target)
	if target == "" {
		return errors.New("target is required")
	}
	if !filepath.IsAbs(target) {
		return fmt.Errorf("target %q must be absolute", mount.Target)
	}
	if filepath.Clean(target) == string(filepath.Separator) {
		return fmt.Errorf("target %q must not be root", mount.Target)
	}
	if mount.Mode != nil {
		if *mount.Mode < 0 || *mount.Mode > 0o777 {
			return fmt.Errorf("mode %04o is invalid; must be between 0000 and 0777", *mount.Mode)
		}
	}
	return nil
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
	if hasHostname && len(rule.ICMP) > 0 {
		return errors.New("icmp is only supported with cidr rules")
	}
	if len(rule.Ports) == 0 && len(rule.ICMP) == 0 {
		return errors.New("must specify at least one of ports or icmp")
	}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d", port)
		}
	}
	for i, icmpRule := range rule.ICMP {
		if icmpRule.Type < 0 || icmpRule.Type > 255 {
			return fmt.Errorf("icmp[%d].type %d is invalid; must be between 0 and 255", i, icmpRule.Type)
		}
		if icmpRule.Code != nil && (*icmpRule.Code < 0 || *icmpRule.Code > 255) {
			return fmt.Errorf("icmp[%d].code %d is invalid; must be between 0 and 255", i, *icmpRule.Code)
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
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	if host == "" {
		return errors.New("must be non-empty")
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname %q is too long", hostname)
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
	// Match legacy evaluator constraints: total hostname length <= 253 and each
	// label length <= 63.
	if len(host) > 253 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return ""
		}
		if len(label) > 63 {
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
