package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsFromStructuredFixtureYAML(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  hostname: box
  workdir: .
network:
  mode: monitor
  subnet: 100.96.0.0/30
  dns:
    bind_addr: auto
  transparent_proxy:
    mode: peek
docker:
  ready_timeout: 10s
policy:
  egress: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
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
	if got.Policy.Egress[0].Hostname != "example.com" {
		t.Fatalf("policy.egress[0].hostname = %q, want %q", got.Policy.Egress[0].Hostname, "example.com")
	}
	if got.Policy.Egress[0].CIDR != "" {
		t.Fatalf("policy.egress[0].cidr = %q, want empty", got.Policy.Egress[0].CIDR)
	}
	if len(got.Policy.Egress[0].Transport) != 1 {
		t.Fatalf("policy.egress[0].transport len = %d, want 1", len(got.Policy.Egress[0].Transport))
	}
	if got.Policy.Egress[0].Transport[0].Protocol != "tcp" {
		t.Fatalf("policy.egress[0].transport[0].protocol = %q, want %q", got.Policy.Egress[0].Transport[0].Protocol, "tcp")
	}
	if len(got.Policy.Egress[0].Transport[0].Ports) != 1 || got.Policy.Egress[0].Transport[0].Ports[0] != 443 {
		t.Fatalf("policy.egress[0].transport[0].ports = %v, want [443]", got.Policy.Egress[0].Transport[0].Ports)
	}
	if len(got.Policy.Egress[0].ICMP) != 1 {
		t.Fatalf("policy.egress[0].icmp len = %d, want 1", len(got.Policy.Egress[0].ICMP))
	}
	if got.Policy.Egress[0].ICMP[0].Type != 8 || got.Policy.Egress[0].ICMP[0].Code != 0 {
		t.Fatalf("policy.egress[0].icmp[0] = (%d,%d), want (8,0)", got.Policy.Egress[0].ICMP[0].Type, got.Policy.Egress[0].ICMP[0].Code)
	}
	if got.Policy.Egress[1].CIDR != "93.184.216.0/24" {
		t.Fatalf("policy.egress[1].cidr = %q, want %q", got.Policy.Egress[1].CIDR, "93.184.216.0/24")
	}
	if got.Policy.Egress[1].Hostname != "" {
		t.Fatalf("policy.egress[1].hostname = %q, want empty", got.Policy.Egress[1].Hostname)
	}
	if len(got.Policy.Egress[1].Transport) != 1 {
		t.Fatalf("policy.egress[1].transport len = %d, want 1", len(got.Policy.Egress[1].Transport))
	}
	if got.Policy.Egress[1].Transport[0].Protocol != "udp" {
		t.Fatalf("policy.egress[1].transport[0].protocol = %q, want %q", got.Policy.Egress[1].Transport[0].Protocol, "udp")
	}
	if len(got.Policy.Egress[1].Transport[0].Ports) != 1 || got.Policy.Egress[1].Transport[0].Ports[0] != 443 {
		t.Fatalf("policy.egress[1].transport[0].ports = %v, want [443]", got.Policy.Egress[1].Transport[0].Ports)
	}
	if len(got.Policy.Egress[1].ICMP) != 0 {
		t.Fatalf("policy.egress[1].icmp len = %d, want 0", len(got.Policy.Egress[1].ICMP))
	}
}

func TestValidateRejectsEgressRuleWithHostnameAndCIDR(t *testing.T) {
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
	if !strings.Contains(strings.ToLower(err.Error()), "hostname") || !strings.Contains(strings.ToLower(err.Error()), "cidr") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of hostname/cidr exclusivity", err)
	}
}

func TestValidateRejectsEgressRuleWithInvalidProtocol(t *testing.T) {
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
		t.Fatal("ValidateRuntime() error = nil, want invalid transport protocol rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "protocol") && !strings.Contains(strings.ToLower(err.Error()), "transport") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of transport protocol issue", err)
	}
}

func TestValidateRejectsEgressRuleWithInvalidICMPTuple(t *testing.T) {
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
		t.Fatal("ValidateRuntime() error = nil, want invalid icmp tuple rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "icmp") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of icmp tuple issue", err)
	}
}

func TestValidateRejectsEgressRuleWithIPv6CIDR(t *testing.T) {
	cfg := Config{}
	cfg.Network.Mode = "enforce"
	cfg.Policy.Egress = []EgressRule{{
		CIDR: "2001:db8::/64",
		Transport: []TransportRule{{
			Protocol: "tcp",
			Ports:    []int{443},
		}},
	}}

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want IPv6 CIDR rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cidr") || !strings.Contains(strings.ToLower(err.Error()), "ipv4") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of ipv4 cidr validation", err)
	}
}

func TestValidateRejectsEgressRuleWithEmptyTransportPorts(t *testing.T) {
	cfg := Config{}
	cfg.Network.Mode = "enforce"
	cfg.Policy.Egress = []EgressRule{{
		Hostname: "example.com",
		Transport: []TransportRule{{
			Protocol: "tcp",
			Ports:    []int{},
		}},
	}}

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want empty transport ports rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "transport") || !strings.Contains(strings.ToLower(err.Error()), "ports") {
		t.Fatalf("ValidateRuntime() error = %q, want mention of transport ports validation", err)
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
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: monitor
  dns:
    bind_addr: auto
policy:
  egress: []
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
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
