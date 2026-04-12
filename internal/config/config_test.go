package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsBuildKitSection(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
buildkit:
  enabled: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want rejection for buildkit section")
	}
	if !strings.Contains(err.Error(), "buildkit") {
		t.Fatalf("Load() error = %q, want mention of buildkit", err)
	}
}

func TestLoadDefaultsFromRecoveredBoxYAML(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}

	got, err := Load(filepath.Join(repoRoot, "box.yaml"), repoRoot)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Sandbox.Rootfs != "host-overlay" {
		t.Fatalf("sandbox.rootfs = %q, want %q", got.Sandbox.Rootfs, "host-overlay")
	}
	if got.Sandbox.Hostname != "box" {
		t.Fatalf("sandbox.hostname = %q, want %q", got.Sandbox.Hostname, "box")
	}
	if got.Sandbox.InheritEnv {
		t.Fatalf("sandbox.inherit_env = %t, want false by default", got.Sandbox.InheritEnv)
	}
	if !got.Sandbox.WorkdirOverlayEnabled() {
		t.Fatalf("sandbox.workdir_overlay = %v, want enabled by default", got.Sandbox.WorkdirOverlay)
	}
	if got.Network.Subnet != "100.96.0.0/24" {
		t.Fatalf("subnet = %q, want %q", got.Network.Subnet, "100.96.0.0/24")
	}
	if got.Network.DNS.BindAddr != "auto" {
		t.Fatalf("dns.bind_addr = %q, want %q", got.Network.DNS.BindAddr, "auto")
	}
	if got.Network.Envoy.Mode != "peek" {
		t.Fatalf("envoy.mode = %q, want %q", got.Network.Envoy.Mode, "peek")
	}
}

func TestLoadResolvesWorkdirRelativeToInvocationDir(t *testing.T) {
	invocationDir := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: rel/project
network:
  mode: monitor
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, invocationDir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := filepath.Join(invocationDir, "rel/project")
	if got.Sandbox.Workdir != want {
		t.Fatalf("sandbox.workdir = %q, want %q", got.Sandbox.Workdir, want)
	}
}

func TestLoadDefaultsWorkdirOverlayToTrueWhenOmitted(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !got.Sandbox.WorkdirOverlayEnabled() {
		t.Fatalf("sandbox.workdir_overlay = %v, want default enabled when omitted", got.Sandbox.WorkdirOverlay)
	}
}

func TestLoadRejectsUnknownNetworkPolicyRuleKeys(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
  policy:
    - hostname: example.com
      ports: [443]
      frob: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want rejection for unknown network.policy rule key")
	}
	if !strings.Contains(err.Error(), "frob") {
		t.Fatalf("Load() error = %q, want mention of unknown key frob", err)
	}
}

func TestLoadHonorsExplicitDisabledWorkdirOverlay(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
  workdir_overlay: false
network:
  mode: monitor
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Sandbox.WorkdirOverlayEnabled() {
		t.Fatalf("sandbox.workdir_overlay = %v, want disabled when explicitly false", got.Sandbox.WorkdirOverlay)
	}
}

func TestValidateRejectsEnvoyMITMAtRuntimeBoundary(t *testing.T) {
	cfg := Config{}
	cfg.Network.Envoy.Enabled = true
	cfg.Network.Envoy.Mode = "mitm"

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want rejection for mitm mode")
	}
	if !strings.Contains(err.Error(), "network.envoy.mode=mitm") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of network.envoy.mode=mitm", err)
	}
}

func TestLoadRejectsDockerSection(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
docker:
  enabled: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want rejection for docker section")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Fatalf("Load() error = %q, want mention of docker", err)
	}
}

func TestValidateRejectsEnvoyMITMEvenWhenDisabled(t *testing.T) {
	cfg := Config{}
	cfg.Network.Envoy.Enabled = false
	cfg.Network.Envoy.Mode = "mitm"

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want rejection for mitm mode regardless of enabled flag")
	}
	if !strings.Contains(err.Error(), "network.envoy.mode=mitm") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of network.envoy.mode=mitm", err)
	}
}

func TestValidateRejectsNetworkPolicyRuleWithHostnameAndCIDR(t *testing.T) {
	t.Run("mutually exclusive selectors", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "example.com",
			CIDR:     "93.184.216.0/24",
			Ports:    []int{443},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want selector rejection")
		}
	})

	t.Run("invalid cidr", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			CIDR:  "93.184.216.0/33",
			Ports: []int{443},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid cidr rejection")
		}
	})

	t.Run("invalid port", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{65536},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid port rejection")
		}
	})
}

func TestValidateAcceptsMonitorAndEnforceModes(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce", "MONITOR", "ENFORCE"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{}
			cfg.Network.Mode = mode
			if err := ValidateRuntime(cfg); err != nil {
				t.Fatalf("ValidateRuntime() error = %v, want nil for mode %q", err, mode)
			}
		})
	}
}

func TestValidateRejectsDeprecatedNetworkModes(t *testing.T) {
	for _, mode := range []string{"deny-all", "enforce-dns", "enforce-proxy"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{}
			cfg.Network.Mode = mode

			err := ValidateRuntime(cfg)
			if err == nil {
				t.Fatalf("ValidateRuntime() error = nil, want rejection for mode %q", mode)
			}
			if !strings.Contains(err.Error(), "network.mode") {
				t.Fatalf("ValidateRuntime() error = %q, want mention of network.mode", err.Error())
			}
		})
	}
}

func TestDNSBindAddrAutoUsesSentinelValueUntilRuntimePlanning(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}

	got, err := Load(filepath.Join(repoRoot, "box.yaml"), repoRoot)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Network.DNS.BindAddr != "auto" {
		t.Fatalf("dns.bind_addr = %q, want %q", got.Network.DNS.BindAddr, "auto")
	}
	if err := ValidateRuntime(got); err != nil {
		t.Fatalf("ValidateRuntime() error = %v, want nil for bind_addr=auto", err)
	}
}

func TestLoadNetworkPolicyRules(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
  policy:
    - hostname: example.com
      ports: [80, 443]
      http:
        path:
          - /foo/*
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Network.Policy) != 1 {
		t.Fatalf("network.policy len = %d, want 1", len(got.Network.Policy))
	}
}

func TestLoadRejectsLegacyTopLevelPolicy(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
policy:
  allow_domains: ["example.com"]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want legacy policy rejection")
	}
}

func TestValidateRejectsInvalidNetworkPolicyRule(t *testing.T) {
	t.Run("rejects invalid wildcard hostname", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "*.bad.*.example",
			Ports:    []int{443},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid rule rejection")
		}
	})

	t.Run("rejects invalid port", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{0},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid rule rejection")
		}
	})

	t.Run("rejects empty http.path entry", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &HTTPPolicyConfig{
				Path: []string{""},
			},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid rule rejection")
		}
	})

	t.Run("rejects invalid http.path glob", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Network.Policy = []NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &HTTPPolicyConfig{
				Path: []string{"/["},
			},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want invalid glob rejection")
		}
		if !strings.Contains(err.Error(), "not a valid glob") {
			t.Fatalf("ValidateRuntime() error = %q, want mention of invalid glob", err.Error())
		}
	})
}

func TestValidateAcceptsValidWildcardHostname(t *testing.T) {
	cfg := Config{}
	cfg.Network.Mode = "enforce"
	cfg.Network.Policy = []NetworkPolicyRule{{
		Hostname: "*.example.com",
		Ports:    []int{443},
	}}

	if err := ValidateRuntime(cfg); err != nil {
		t.Fatalf("ValidateRuntime() error = %v, want nil", err)
	}
}

func TestLoadPopulatesLegacyTransparentProxyFromNetworkEnvoy(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
  envoy:
    enabled: true
    mode: peek
    http_port: 18080
    tls_port: 18443
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.Network.TransparentProxy.Enabled != got.Network.Envoy.Enabled ||
		got.Network.TransparentProxy.Mode != got.Network.Envoy.Mode ||
		got.Network.TransparentProxy.HTTPPort != got.Network.Envoy.HTTPPort ||
		got.Network.TransparentProxy.TLSPort != got.Network.Envoy.TLSPort {
		t.Fatalf("legacy transparent proxy shim did not mirror network.envoy: got=%#v envoy=%#v", got.Network.TransparentProxy, got.Network.Envoy)
	}
}

func TestLoadLegacyPolicyShimIgnoresWildcardHostnameRules(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
  policy:
    - hostname: "*.example.com"
      ports: [443]
    - hostname: example.com
      ports: [443]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Network.Policy) != 2 {
		t.Fatalf("network.policy len = %d, want 2", len(got.Network.Policy))
	}

	for _, d := range got.Policy.AllowDomains {
		if strings.Contains(d, "*") {
			t.Fatalf("legacy policy allow_domains contains wildcard %q; want wildcard rules ignored in shim", d)
		}
	}
	for _, rule := range got.Policy.Egress {
		if strings.Contains(rule.Hostname, "*") {
			t.Fatalf("legacy policy egress contains wildcard hostname %q; want wildcard rules ignored in shim", rule.Hostname)
		}
	}
	foundExample := false
	for _, d := range got.Policy.AllowDomains {
		if d == "example.com" {
			foundExample = true
			break
		}
	}
	if !foundExample {
		t.Fatalf("legacy policy allow_domains = %#v, want example.com present", got.Policy.AllowDomains)
	}
}
