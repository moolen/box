package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBuildKitDefaults(t *testing.T) {
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

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !got.BuildKit.Enabled {
		t.Fatal("buildkit.enabled = false, want true")
	}
	if got.BuildKit.HelperPathValue() != "/box/bin/buildctl-daemonless.sh" {
		t.Fatalf("buildkit.helper_path = %q, want %q", got.BuildKit.HelperPathValue(), "/box/bin/buildctl-daemonless.sh")
	}
	if got.BuildKit.StateDirValue() != "/var/cache/buildkit" {
		t.Fatalf("buildkit.state_dir = %q, want %q", got.BuildKit.StateDirValue(), "/var/cache/buildkit")
	}
	if got.BuildKit.RunDirValue() != "/run/buildkit" {
		t.Fatalf("buildkit.run_dir = %q, want %q", got.BuildKit.RunDirValue(), "/run/buildkit")
	}
	if !got.BuildKit.DaemonlessValue() {
		t.Fatal("buildkit.daemonless = false, want true by default")
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
	if got.Network.TransparentProxy.Mode != "peek" {
		t.Fatalf("transparent_proxy.mode = %q, want %q", got.Network.TransparentProxy.Mode, "peek")
	}
	if got.BuildKit.HelperPathValue() != "/box/bin/buildctl-daemonless.sh" {
		t.Fatalf("buildkit.helper_path = %q, want %q", got.BuildKit.HelperPathValue(), "/box/bin/buildctl-daemonless.sh")
	}
	if got.BuildKit.StateDirValue() != "/var/cache/buildkit" {
		t.Fatalf("buildkit.state_dir = %q, want %q", got.BuildKit.StateDirValue(), "/var/cache/buildkit")
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

func TestLoadRejectsUnknownPolicyKeys(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
policy:
  allow_cidrs: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want rejection for unknown policy key")
	}
	if !strings.Contains(err.Error(), "allow_cidrs") {
		t.Fatalf("Load() error = %q, want mention of unknown key allow_cidrs", err)
	}
}

func TestLoadStructuredEgressPolicy(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
policy:
  egress:
    - hostname: example.com
      transport:
        - protocol: tcp
          ports: [443]
      icmp:
        - type: 8
          code: 0
    - cidr: 93.184.216.0/24
      transport:
        - protocol: udp
          ports: [443]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Policy.Egress) != 2 {
		t.Fatalf("policy.egress len = %d, want 2", len(got.Policy.Egress))
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

func TestValidateRejectsTransparentProxyMITMAtRuntimeBoundary(t *testing.T) {
	cfg := Config{}
	cfg.Network.TransparentProxy.Enabled = true
	cfg.Network.TransparentProxy.Mode = "mitm"

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want rejection for mitm mode")
	}
	if !strings.Contains(err.Error(), "network.transparent_proxy.mode=mitm") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of network.transparent_proxy.mode=mitm", err)
	}
}

func TestValidateRejectsDockerDaemonMode(t *testing.T) {
	cfg := Config{}
	cfg.Docker.Enabled = true

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want rejection for docker.enabled=true")
	}
	if !strings.Contains(err.Error(), "docker.enabled") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of docker.enabled", err)
	}
}

func TestValidateRejectsTransparentProxyMITMEvenWhenDisabled(t *testing.T) {
	cfg := Config{}
	cfg.Network.TransparentProxy.Enabled = false
	cfg.Network.TransparentProxy.Mode = "mitm"

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want rejection for mitm mode regardless of enabled flag")
	}
	if !strings.Contains(err.Error(), "network.transparent_proxy.mode=mitm") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of network.transparent_proxy.mode=mitm", err)
	}
}

func TestValidateRejectsEgressRuleWithHostnameAndCIDR(t *testing.T) {
	t.Run("mutually exclusive selectors", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Policy.Egress = []EgressRule{{
			Hostname: "example.com",
			CIDR:     "93.184.216.0/24",
			Transport: []TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want selector rejection")
		}
	})

	t.Run("invalid transport protocol", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Policy.Egress = []EgressRule{{
			Hostname: "example.com",
			Transport: []TransportRule{{
				Protocol: "sctp",
				Ports:    []int{443},
			}},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want protocol rejection")
		}
	})

	t.Run("invalid icmp tuple", func(t *testing.T) {
		cfg := Config{}
		cfg.Network.Mode = "enforce"
		cfg.Policy.Egress = []EgressRule{{
			CIDR: "93.184.216.0/24",
			ICMP: []ICMPRule{{
				Type: 300,
				Code: -1,
			}},
		}}

		err := ValidateRuntime(cfg)
		if err == nil {
			t.Fatal("ValidateRuntime() error = nil, want icmp tuple rejection")
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
