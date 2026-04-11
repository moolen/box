package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if got.Network.Subnet != "100.96.0.0/30" {
		t.Fatalf("subnet = %q, want %q", got.Network.Subnet, "100.96.0.0/30")
	}
	if got.Network.DNS.BindAddr != "auto" {
		t.Fatalf("dns.bind_addr = %q, want %q", got.Network.DNS.BindAddr, "auto")
	}
	if got.Network.TransparentProxy.Mode != "peek" {
		t.Fatalf("transparent_proxy.mode = %q, want %q", got.Network.TransparentProxy.Mode, "peek")
	}
	if got.Docker.ReadyTimeout.String() != "10s" {
		t.Fatalf("docker.ready_timeout = %q, want %q", got.Docker.ReadyTimeout, "10s")
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
