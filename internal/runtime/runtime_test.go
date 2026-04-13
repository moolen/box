package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gvisor-net/internal/config"
	"gvisor-net/internal/netns"
	"gvisor-net/internal/policyd"
)

func TestRunCreatesStateDirAndEventLog(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("enforce")

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-a" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rt.Manifest.StateDir != filepath.Join(stateRoot, "runtime-a") {
		t.Fatalf("Manifest.StateDir = %q, want %q", rt.Manifest.StateDir, filepath.Join(stateRoot, "runtime-a"))
	}
	if _, err := os.Stat(rt.Manifest.StateDir); err != nil {
		t.Fatalf("state dir stat error = %v", err)
	}
	if _, err := os.Stat(rt.Manifest.EventLogPath); err != nil {
		t.Fatalf("event log stat error = %v", err)
	}
	if _, err := os.Stat(rt.Manifest.ManifestPath); err != nil {
		t.Fatalf("manifest stat error = %v", err)
	}
}

func TestRunRecordsRandomizedEnvoyPortsAndCAAssets(t *testing.T) {
	t.Parallel()

	cfg := testConfig("enforce")

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-envoy-ca" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rt.Manifest.Envoy.ExplicitPort == 0 || rt.Manifest.Envoy.TransparentPort == 0 || rt.Manifest.Envoy.DNSPort == 0 {
		t.Fatalf("Manifest.Envoy = %#v, want randomized non-zero ports", rt.Manifest.Envoy)
	}
	if rt.Manifest.Envoy.ExplicitPort == rt.Manifest.Envoy.TransparentPort ||
		rt.Manifest.Envoy.ExplicitPort == rt.Manifest.Envoy.DNSPort ||
		rt.Manifest.Envoy.TransparentPort == rt.Manifest.Envoy.DNSPort {
		t.Fatalf("Manifest.Envoy = %#v, want distinct listener ports", rt.Manifest.Envoy)
	}
	if strings.TrimSpace(rt.Manifest.CA.CertPath) == "" {
		t.Fatalf("Manifest.CA.CertPath = %q, want non-empty", rt.Manifest.CA.CertPath)
	}
	if strings.TrimSpace(rt.Manifest.CA.KeyPath) == "" {
		t.Fatalf("Manifest.CA.KeyPath = %q, want non-empty", rt.Manifest.CA.KeyPath)
	}
	if strings.TrimSpace(rt.Manifest.CA.SandboxCertPath) == "" {
		t.Fatalf("Manifest.CA.SandboxCertPath = %q, want non-empty", rt.Manifest.CA.SandboxCertPath)
	}
	if rt.Manifest.Envoy.BootstrapPath == "" {
		t.Fatalf("Manifest.Envoy.BootstrapPath = %q, want non-empty", rt.Manifest.Envoy.BootstrapPath)
	}

	certPEM, err := os.ReadFile(rt.Manifest.CA.CertPath)
	if err != nil {
		t.Fatalf("ReadFile(CA cert) error = %v", err)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("CA cert = %q, want PEM certificate", string(certPEM))
	}
	if _, err := os.Stat(rt.Manifest.CA.KeyPath); err != nil {
		t.Fatalf("CA key stat error = %v", err)
	}
}

func TestMonitorModeRewritesResolvConfToGatewayIP(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Network.DNS.Upstream = []string{"1.1.1.1:53"}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-a" },
		CommandExec: noopCommandExec{},
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(rt.Manifest.ResolvConf, "nameserver "+rt.Manifest.GatewayIP) {
		t.Fatalf("Manifest.ResolvConf = %q, want nameserver gateway IP", rt.Manifest.ResolvConf)
	}
	if strings.Contains(rt.Manifest.ResolvConf, "nameserver 127.0.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, must not use localhost in monitor mode", rt.Manifest.ResolvConf)
	}
}

func TestMonitorModeStartsPolicyServiceAndEnvoyWithScopedResources(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Network.DNS.Upstream = []string{"1.1.1.1:53"}

	var policyReq PolicyServiceStartRequest
	var policyCalled bool
	var envoyReq EnvoyStartRequest
	var envoyCalled bool
	exec := &recordingCommandExec{}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-b" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(_ context.Context, req PolicyServiceStartRequest) (Runner, error) {
			policyCalled = true
			policyReq = req
			return noopRunner{}, nil
		},
		StartEnvoy: func(_ context.Context, req EnvoyStartRequest) (Runner, error) {
			envoyCalled = true
			envoyReq = req
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !policyCalled {
		t.Fatalf("StartPolicyService was not called in monitor mode")
	}
	if !envoyCalled {
		t.Fatalf("StartEnvoy was not called in monitor mode")
	}
	if policyReq.Mode != "monitor" {
		t.Fatalf("PolicyService request mode = %q, want %q", policyReq.Mode, "monitor")
	}
	if policyReq.GatewayIP != rt.Manifest.GatewayIP {
		t.Fatalf("PolicyService request gateway ip = %q, want %q", policyReq.GatewayIP, rt.Manifest.GatewayIP)
	}
	if !reflect.DeepEqual(policyReq.DNSUpstream, cfg.Network.DNS.Upstream) {
		t.Fatalf("PolicyService DNSUpstream = %#v, want %#v", policyReq.DNSUpstream, cfg.Network.DNS.Upstream)
	}
	if strings.TrimSpace(policyReq.ListenAddr) == "" {
		t.Fatalf("PolicyService ListenAddr = %q, want non-empty", policyReq.ListenAddr)
	}
	if strings.TrimSpace(policyReq.DNSListenAddr) == "" {
		t.Fatalf("PolicyService DNSListenAddr = %q, want non-empty", policyReq.DNSListenAddr)
	}
	if envoyReq.ExplicitPort != rt.Manifest.Envoy.ExplicitPort {
		t.Fatalf("Envoy request explicit port = %d, want %d", envoyReq.ExplicitPort, rt.Manifest.Envoy.ExplicitPort)
	}
	if envoyReq.TransparentPort != rt.Manifest.Envoy.TransparentPort {
		t.Fatalf("Envoy request transparent port = %d, want %d", envoyReq.TransparentPort, rt.Manifest.Envoy.TransparentPort)
	}
	if envoyReq.DNSPort != rt.Manifest.Envoy.DNSPort {
		t.Fatalf("Envoy request dns port = %d, want %d", envoyReq.DNSPort, rt.Manifest.Envoy.DNSPort)
	}
	if !reflect.DeepEqual(envoyReq.DNSUpstream, []string{policyReq.DNSListenAddr}) {
		t.Fatalf("Envoy request DNSUpstream = %#v, want local policyd resolver %#v", envoyReq.DNSUpstream, []string{policyReq.DNSListenAddr})
	}
	if envoyReq.PolicyListenAddr != policyReq.ListenAddr {
		t.Fatalf("Envoy request policy addr = %q, want %q", envoyReq.PolicyListenAddr, policyReq.ListenAddr)
	}

	resources, err := netns.ResourcesForRuntimeID("runtime-monitor-b")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error = %v", err)
	}
	resources.SubnetCIDR = rt.Manifest.Net.SubnetCIDR
	setupPlan, err := netns.BuildSetupPlan(resources)
	if err != nil {
		t.Fatalf("BuildSetupPlan() error = %v", err)
	}

	wantSetupPrefix := []string{
		"ip netns add " + resources.NetNS,
		"ip link add " + resources.HostVeth + " type veth peer name " + resources.GuestVeth,
		"ip link set " + resources.GuestVeth + " netns " + resources.NetNS,
		"ip addr add " + setupPlan.GatewayCIDR + " dev " + resources.HostVeth,
		"ip link set " + resources.HostVeth + " up",
		"ip netns exec " + resources.NetNS + " ip link set lo up",
		"ip netns exec " + resources.NetNS + " ip addr add " + setupPlan.SandboxCIDR + " dev " + resources.GuestVeth,
		"ip netns exec " + resources.NetNS + " ip link set " + resources.GuestVeth + " up",
		"ip netns exec " + resources.NetNS + " ip route add default via " + setupPlan.GatewayIP + " dev " + resources.GuestVeth,
	}
	setupStart := slices.Index(exec.calls, wantSetupPrefix[0])
	if setupStart == -1 {
		t.Fatalf("command exec calls = %#v, want netns setup command %q", exec.calls, wantSetupPrefix[0])
	}
	if len(exec.calls[setupStart:]) < len(wantSetupPrefix) {
		t.Fatalf("command exec calls too short = %#v", exec.calls)
	}
	for i, want := range wantSetupPrefix {
		if exec.calls[setupStart+i] != want {
			t.Fatalf("setup command %d = %q, want %q", i, exec.calls[setupStart+i], want)
		}
	}

	if !exec.contains("nft add table inet " + resources.TableName) {
		t.Fatalf("firewall setup commands = %#v, want nft table scoped to runtime", exec.calls)
	}
	if !exec.contains("iifname " + resources.HostVeth) {
		t.Fatalf("firewall setup commands = %#v, want host-veth scoping", exec.calls)
	}
	if !exec.contains("ip rule add fwmark") || !exec.contains("lookup") {
		t.Fatalf("routing setup commands = %#v, want policy routing setup", exec.calls)
	}
}

func TestRunUsesInjectedNetworkAllocation(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Network.Subnet = "100.96.0.0/24"

	var preflightReq MonitorPreflightRequest
	exec := &recordingCommandExec{}
	allocated := netns.Resources{
		NetNS:      "box-dynamic",
		HostVeth:   "vethhdynamic",
		GuestVeth:  "vethgdynamic",
		TableName:  "box_dynamic",
		FWMark:     4242,
		RouteTable: 20042,
		SubnetCIDR: "100.96.0.4/30",
	}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-allocated" },
		CommandExec: exec,
		AllocateNetResources: func(context.Context, string, string) (netns.Resources, error) {
			return allocated, nil
		},
		MonitorPreflight: func(_ context.Context, req MonitorPreflightRequest) error {
			preflightReq = req
			return nil
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantNet := NetResources{
		NetNS:      allocated.NetNS,
		HostVeth:   allocated.HostVeth,
		GuestVeth:  allocated.GuestVeth,
		TableName:  allocated.TableName,
		FWMark:     allocated.FWMark,
		RouteTable: allocated.RouteTable,
		SubnetCIDR: allocated.SubnetCIDR,
	}
	if preflightReq.Net != wantNet {
		t.Fatalf("MonitorPreflightRequest.Net = %#v, want %#v", preflightReq.Net, wantNet)
	}
	if rt.Manifest.Net != wantNet {
		t.Fatalf("Manifest.Net = %#v, want %#v", rt.Manifest.Net, wantNet)
	}
	if rt.Manifest.GatewayIP != "100.96.0.5" {
		t.Fatalf("Manifest.GatewayIP = %q, want %q", rt.Manifest.GatewayIP, "100.96.0.5")
	}
	mustContainCall(t, exec.calls, "ip addr add 100.96.0.5/30 dev vethhdynamic")
	mustContainCall(t, exec.calls, "ip netns exec box-dynamic ip addr add 100.96.0.6/30 dev vethgdynamic")
	mustContainCall(t, exec.calls, "ip rule add fwmark 4242 lookup 20042")
}

func TestMonitorModeRecordsOwnedNetworkTeardownCommands(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	exec := &recordingCommandExec{}
	resources, err := netns.ResourcesForRuntimeID("runtime-monitor-teardown")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error = %v", err)
	}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-teardown" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	mustContain(t, strings.Join(rt.Manifest.TeardownCmds, "\n"), "ip netns del "+resources.NetNS)
	mustContain(t, strings.Join(rt.Manifest.TeardownCmds, "\n"), "ip link del "+resources.HostVeth)
}

func TestRunPreparesWorkdirOverlayByDefaultAndRecordsOwnedUnmount(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	repoRoot := t.TempDir()
	cfg := testConfig("enforce")
	cfg.Sandbox.Workdir = repoRoot

	exec := &recordingCommandExec{}
	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-overlay-default" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantMerged := filepath.Join(stateRoot, "runtime-overlay-default", "workdir", "merged")
	if rt.Manifest.WorkdirMountSource != wantMerged {
		t.Fatalf("Manifest.WorkdirMountSource = %q, want %q", rt.Manifest.WorkdirMountSource, wantMerged)
	}
	mustContainCall(t, exec.calls, "mount -t overlay overlay")
	mustContainCall(t, exec.calls, "lowerdir="+repoRoot)
	mustContain(t, strings.Join(rt.Manifest.TeardownCmds, "\n"), "umount "+wantMerged)
}

func TestRunSkipsWorkdirOverlayWhenExplicitlyDisabled(t *testing.T) {
	t.Parallel()

	cfg := testConfig("enforce")
	cfg.Sandbox.Workdir = t.TempDir()
	cfg.Sandbox.WorkdirOverlay = boolPtr(false)

	exec := &recordingCommandExec{}
	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-overlay-disabled" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rt.Manifest.WorkdirMountSource != "" {
		t.Fatalf("Manifest.WorkdirMountSource = %q, want empty when overlay disabled", rt.Manifest.WorkdirMountSource)
	}
	for _, call := range exec.calls {
		if strings.Contains(call, "mount -t overlay overlay") {
			t.Fatalf("unexpected overlay mount command: %#v", exec.calls)
		}
	}
}

func TestRunStartsPolicyServiceBeforeEnvoy(t *testing.T) {
	t.Parallel()

	var order []string

	_, err := Run(context.Background(), Request{
		Config:    testConfig("enforce"),
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-start-order" },
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			order = append(order, "policyd")
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			order = append(order, "envoy")
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"policyd", "envoy"}) {
		t.Fatalf("startup order = %#v, want policyd before envoy", order)
	}
}

func TestMonitorModeCapturesMonitorSummaryFromPolicyEvents(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Policy.AllowDomains = []string{"example.com"}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-summary" },
		CommandExec: noopCommandExec{},
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(_ context.Context, req PolicyServiceStartRequest) (Runner, error) {
			if req.OnEvent == nil {
				t.Fatalf("PolicyServiceStartRequest.OnEvent = nil, want callback")
			}
			req.OnEvent(policyd.Event{
				Type:     "dns",
				Protocol: "dns",
				Hostname: "dns.example.com",
			})
			req.OnEvent(policyd.Event{
				Type:     "http",
				Protocol: "http",
				Hostname: "api.example.com",
				Method:   "GET",
				Path:     "/hello",
			})
			req.OnEvent(policyd.Event{
				Type:     "tls",
				Protocol: "https",
				Hostname: "tls.example.com",
			})
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	summary := rt.MonitorSummary()
	mustContain(t, summary, "Monitor summary")
	mustContain(t, summary, "DNS:")
	mustContain(t, summary, "dns.example.com [ALLOW]: 1")
	mustContain(t, summary, "HTTP:")
	mustContain(t, summary, "GET api.example.com [ALLOW]: 1")
	mustContain(t, summary, "TLS:")
	mustContain(t, summary, "tls.example.com [ALLOW]: 1")
	mustContain(t, summary, "Total events: 3")
}

func TestMonitorModeAppendsRawTrafficEventsToEventLog(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-events" },
		CommandExec: noopCommandExec{},
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(_ context.Context, req PolicyServiceStartRequest) (Runner, error) {
			req.OnEvent(policyd.Event{
				Type:     "dns",
				Protocol: "dns",
				Hostname: "dns.example.com",
			})
			req.OnEvent(policyd.Event{
				Type:     "http",
				Protocol: "http",
				Hostname: "api.example.com",
				Method:   "POST",
				Path:     "/submit",
			})
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	eventLog, err := os.ReadFile(rt.Manifest.EventLogPath)
	if err != nil {
		t.Fatalf("ReadFile(event log) error = %v", err)
	}
	text := string(eventLog)
	mustContain(t, text, `"type":"dns"`)
	mustContain(t, text, `"hostname":"dns.example.com"`)
	mustContain(t, text, `"type":"http"`)
	mustContain(t, text, `"protocol":"http"`)
	mustContain(t, text, `"hostname":"api.example.com"`)
	mustContain(t, text, `"method":"POST"`)
	mustContain(t, text, `"path":"/submit"`)
}

func TestEnforceModeForcesGatewayResolvConf(t *testing.T) {
	t.Parallel()

	cfg := testConfig("enforce")

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-c" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(rt.Manifest.ResolvConf, "nameserver "+rt.Manifest.GatewayIP) {
		t.Fatalf("Manifest.ResolvConf = %q, want gateway nameserver in enforce mode", rt.Manifest.ResolvConf)
	}
	if strings.Contains(rt.Manifest.ResolvConf, "nameserver 127.0.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, must not use localhost nameserver in enforce mode", rt.Manifest.ResolvConf)
	}
}

func TestMonitorPreflightConflictPreventsMonitorMutationAndTeardown(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("monitor")

	exec := &recordingCommandExec{}
	policydCalled := false
	envoyCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-preflight-conflict" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return errors.New("nft table already owned by another runtime")
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			policydCalled = true
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			envoyCalled = true
			return noopRunner{}, nil
		},
	})
	if err == nil {
		t.Fatalf("Run() error = nil, want conflict error")
	}
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("Run() error = %v, want ErrResourceConflict", err)
	}

	if len(exec.calls) != 0 {
		t.Fatalf("command exec calls = %#v, want none when preflight conflicts", exec.calls)
	}
	if policydCalled {
		t.Fatalf("StartPolicyService was called despite monitor preflight conflict")
	}
	if envoyCalled {
		t.Fatalf("StartEnvoy was called despite monitor preflight conflict")
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "runtime-preflight-conflict")); !os.IsNotExist(statErr) {
		t.Fatalf("state dir should be cleaned up on preflight conflict; stat err=%v", statErr)
	}
}

func TestRunCleansTrustedOrphansBeforeMonitorPreflight(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	orphanDir := filepath.Join(stateRoot, "runtime-orphan-preflight")
	orphanCleanupCmd := "nft delete table inet box_orphaned_before_preflight"

	writeOrphanManifestForTest(t, Manifest{
		RuntimeID:    "runtime-orphan-preflight",
		StateRoot:    stateRoot,
		StateDir:     orphanDir,
		ManifestPath: filepath.Join(orphanDir, manifestFileName),
		TeardownCmds: []string{
			orphanCleanupCmd,
		},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(orphanDir, manifestFileName), Kind: PathKindFile},
			{Path: orphanDir, Kind: PathKindDir},
		},
	})

	cfg := testConfig("monitor")
	exec := &recordingCommandExec{}
	preflightCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-live-preflight-order" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			preflightCalled = true
			if !exec.contains(orphanCleanupCmd) {
				t.Fatalf("orphan cleanup command %q was not executed before monitor preflight; calls=%#v", orphanCleanupCmd, exec.calls)
			}
			return nil
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !preflightCalled {
		t.Fatalf("monitor preflight was not called")
	}
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Fatalf("trusted orphan state dir still exists after startup cleanup: %v", err)
	}
}

func TestRunLeavesUntrustedOrphanStateForConflictHandling(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	orphanDir := filepath.Join(stateRoot, "runtime-orphan-untrusted")
	untrustedCleanupCmd := "nft delete table inet box_untrusted_orphan"

	writeOrphanManifestForTest(t, Manifest{
		RuntimeID:    "runtime-not-matching-dir",
		StateRoot:    stateRoot,
		StateDir:     orphanDir,
		ManifestPath: filepath.Join(orphanDir, manifestFileName),
		TeardownCmds: []string{
			untrustedCleanupCmd,
		},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(orphanDir, manifestFileName), Kind: PathKindFile},
			{Path: orphanDir, Kind: PathKindDir},
		},
	})

	cfg := testConfig("monitor")
	exec := &recordingCommandExec{}
	preflightCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-live-strict-conflict" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			preflightCalled = true
			return errors.New("nft table already owned by another runtime")
		},
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
	})
	if err == nil {
		t.Fatalf("Run() error = nil, want ErrResourceConflict for untrusted orphan conflict")
	}
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("Run() error = %v, want ErrResourceConflict", err)
	}
	if !preflightCalled {
		t.Fatalf("monitor preflight was not called")
	}
	if exec.contains(untrustedCleanupCmd) {
		t.Fatalf("untrusted orphan cleanup command %q was executed; calls=%#v", untrustedCleanupCmd, exec.calls)
	}
	if _, statErr := os.Stat(orphanDir); statErr != nil {
		t.Fatalf("untrusted orphan state dir should remain for strict conflict handling; stat err=%v", statErr)
	}
}

func TestMonitorModeWithoutPreflightFailsClosedBeforeMutation(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("monitor")

	exec := &recordingCommandExec{}
	policydCalled := false
	envoyCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-missing-preflight" },
		CommandExec: exec,
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			policydCalled = true
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			envoyCalled = true
			return noopRunner{}, nil
		},
	})
	if err == nil {
		t.Fatalf("Run() error = nil, want conflict error when monitor preflight hook is missing")
	}
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("Run() error = %v, want ErrResourceConflict", err)
	}

	if len(exec.calls) != 0 {
		t.Fatalf("command exec calls = %#v, want none when monitor preflight is missing", exec.calls)
	}
	if policydCalled {
		t.Fatalf("StartPolicyService was called despite missing monitor preflight")
	}
	if envoyCalled {
		t.Fatalf("StartEnvoy was called despite missing monitor preflight")
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "runtime-missing-preflight")); !os.IsNotExist(statErr) {
		t.Fatalf("state dir should be cleaned up when monitor preflight is missing; stat err=%v", statErr)
	}
}

func TestRunNormalizesStateRootToAbsolutePath(t *testing.T) {
	stateRootAbs := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	stateRootRel, err := filepath.Rel(cwd, stateRootAbs)
	if err != nil {
		t.Fatalf("filepath.Rel() error = %v", err)
	}

	cfg := testConfig("enforce")
	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRootRel,
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-abs-state-root" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	defer func() {
		_ = rt.Cleanup(context.Background(), Deps{})
	}()

	wantAbs, err := filepath.Abs(stateRootRel)
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	if rt.Manifest.StateRoot != wantAbs {
		t.Fatalf("Manifest.StateRoot = %q, want %q", rt.Manifest.StateRoot, wantAbs)
	}
	if !filepath.IsAbs(rt.Manifest.StateRoot) {
		t.Fatalf("Manifest.StateRoot = %q, want absolute path", rt.Manifest.StateRoot)
	}
}

func TestRunCreatesMissingStateRootBeforeStartupChecks(t *testing.T) {
	t.Parallel()

	stateRoot := filepath.Join(t.TempDir(), "missing-state-root")
	cfg := testConfig("enforce")

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-create-missing-state-root" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if _, err := os.Stat(stateRoot); err != nil {
		t.Fatalf("state root stat error = %v", err)
	}
	if _, err := os.Stat(rt.Manifest.StateDir); err != nil {
		t.Fatalf("state dir stat error = %v", err)
	}
}

func TestEnforceModeStartsPolicyServiceAndEnvoyWithoutLegacyAllowsetCommands(t *testing.T) {
	t.Parallel()

	cfg := testConfig("enforce")
	cfg.Network.Policy = []config.NetworkPolicyRule{{
		Hostname: "allowed.example.com",
		Ports:    []int{443},
	}}
	cfg.Policy.ExtraAllowedCIDRs = []string{"10.0.0.0/8"}

	exec := &recordingCommandExec{}
	var policyReq PolicyServiceStartRequest
	var policyCalled bool
	var envoyReq EnvoyStartRequest
	var envoyCalled bool

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-enforce" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		StartPolicyService: func(_ context.Context, req PolicyServiceStartRequest) (Runner, error) {
			policyCalled = true
			policyReq = req
			return noopRunner{}, nil
		},
		StartEnvoy: func(_ context.Context, req EnvoyStartRequest) (Runner, error) {
			envoyCalled = true
			envoyReq = req
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	defer func() {
		_ = rt.Cleanup(context.Background(), Deps{CommandExec: exec})
	}()

	if !policyCalled {
		t.Fatalf("StartPolicyService was not called in enforce mode")
	}
	if !envoyCalled {
		t.Fatalf("StartEnvoy was not called in enforce mode")
	}
	if policyReq.Mode != "enforce" {
		t.Fatalf("PolicyService request mode = %q, want %q", policyReq.Mode, "enforce")
	}
	if policyReq.GatewayIP != rt.Manifest.GatewayIP {
		t.Fatalf("PolicyService request gateway ip = %q, want %q", policyReq.GatewayIP, rt.Manifest.GatewayIP)
	}
	if !reflect.DeepEqual(policyReq.Rules, cfg.Network.Policy) {
		t.Fatalf("PolicyService rules = %#v, want %#v", policyReq.Rules, cfg.Network.Policy)
	}
	if !reflect.DeepEqual(policyReq.DNSUpstream, cfg.Network.DNS.Upstream) {
		t.Fatalf("PolicyService DNSUpstream = %#v, want %#v", policyReq.DNSUpstream, cfg.Network.DNS.Upstream)
	}
	if strings.TrimSpace(policyReq.DNSListenAddr) == "" {
		t.Fatalf("PolicyService DNSListenAddr = %q, want non-empty", policyReq.DNSListenAddr)
	}
	if envoyReq.TransparentPort != rt.Manifest.Envoy.TransparentPort {
		t.Fatalf("Envoy request transparent port = %d, want %d", envoyReq.TransparentPort, rt.Manifest.Envoy.TransparentPort)
	}
	if !reflect.DeepEqual(envoyReq.DNSUpstream, []string{policyReq.DNSListenAddr}) {
		t.Fatalf("Envoy request DNSUpstream = %#v, want local policyd resolver %#v", envoyReq.DNSUpstream, []string{policyReq.DNSListenAddr})
	}

	for _, call := range exec.calls {
		if strings.Contains(call, "allow_v4") || strings.Contains(call, "nft add element inet box_") {
			t.Fatalf("legacy allowset command must not be emitted; calls=%#v", exec.calls)
		}
	}
}

func TestCleanupOnlyDeletesManifestOwnedPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stateDir := filepath.Join(root, "run-1")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir) error = %v", err)
	}
	eventPath := filepath.Join(stateDir, "events.log")
	manifestPath := filepath.Join(stateDir, "manifest.json")
	if err := os.WriteFile(eventPath, []byte("events"), 0o644); err != nil {
		t.Fatalf("WriteFile(eventPath) error = %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile(manifestPath) error = %v", err)
	}

	fakeMountedRepo := filepath.Join(root, "mounted-repo")
	if err := os.MkdirAll(fakeMountedRepo, 0o755); err != nil {
		t.Fatalf("MkdirAll(fakeMountedRepo) error = %v", err)
	}
	repoSentinel := filepath.Join(fakeMountedRepo, "README.md")
	if err := os.WriteFile(repoSentinel, []byte("keep me"), 0o644); err != nil {
		t.Fatalf("WriteFile(repoSentinel) error = %v", err)
	}

	manifest := Manifest{
		RuntimeID: "run-1",
		StateRoot: root,
		StateDir:  stateDir,
		ManagedPaths: []ManagedPath{
			{Path: eventPath, Kind: PathKindFile},
			{Path: manifestPath, Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
			{Path: fakeMountedRepo, Kind: PathKindDir},
		},
	}

	err := Cleanup(context.Background(), manifest, CleanupDeps{})
	if err == nil {
		t.Fatalf("Cleanup() error = nil, want error for out-of-scope managed path")
	}
	if !strings.Contains(err.Error(), "outside runtime state dir") {
		t.Fatalf("Cleanup() error = %q, want outside-state-dir hardening error", err.Error())
	}

	if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state dir should be removed; stat err=%v", statErr)
	}
	if _, statErr := os.Stat(fakeMountedRepo); statErr != nil {
		t.Fatalf("fake mounted repo should remain untouched; stat err=%v", statErr)
	}
	if _, statErr := os.Stat(repoSentinel); statErr != nil {
		t.Fatalf("fake mounted repo content should remain untouched; stat err=%v", statErr)
	}
}

func TestCleanupOrderStopsRunnersBeforeNetworkTeardown(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "run-2")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir) error = %v", err)
	}

	var order []string
	exec := &recordingCommandExec{
		onCall: func(call string) {
			order = append(order, "cmd:"+call)
		},
	}

	manifest := Manifest{
		RuntimeID:      "run-2",
		StateRoot:      stateRoot,
		StateDir:       stateDir,
		StartedRunners: []string{"policyd", "envoy", "runsc"},
		NetworkMode:    "monitor",
		Net: NetResources{
			NetNS:      "box-deadbeef",
			HostVeth:   "vethhdeadbeef",
			GuestVeth:  "vethgdeadbeef",
			TableName:  "box_deadbeef",
			FWMark:     257,
			RouteTable: 10001,
		},
		TeardownCmds: []string{
			"nft delete table inet box_deadbeef",
			"ip rule del fwmark 257 lookup 10001",
		},
		ManagedPaths: []ManagedPath{
			{Path: stateDir, Kind: PathKindDir},
		},
	}

	err := Cleanup(context.Background(), manifest, CleanupDeps{
		CommandExec: exec,
		StopRunner: func(name string) error {
			order = append(order, "stop:"+name)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if len(order) < 4 {
		t.Fatalf("cleanup order too short: %#v", order)
	}
	if order[0] != "stop:runsc" || order[1] != "stop:envoy" || order[2] != "stop:policyd" {
		t.Fatalf("runner stop order = %#v, want reverse-start order runsc->envoy->policyd", order)
	}
	if !strings.HasPrefix(order[3], "cmd:") {
		t.Fatalf("expected network teardown commands after runner stops, got %#v", order)
	}
}

func TestCleanupAttemptsAllTeardownCommandsAndAggregatesErrors(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "run-3")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir) error = %v", err)
	}

	manifest := Manifest{
		RuntimeID:   "run-3",
		StateRoot:   stateRoot,
		StateDir:    stateDir,
		NetworkMode: "monitor",
		Net: NetResources{
			NetNS:      "box-beaded01",
			HostVeth:   "vethhbeaded01",
			TableName:  "box_beaded01",
			FWMark:     313,
			RouteTable: 10999,
		},
		TeardownCmds: []string{
			"nft delete table inet box_beaded01",
			"ip rule del fwmark 313 lookup 10999",
			"ip route del local 0.0.0.0/0 dev lo table 10999",
			"ip link del vethhbeaded01",
			"ip netns del box-beaded01",
		},
		ManagedPaths: []ManagedPath{
			{Path: stateDir, Kind: PathKindDir},
		},
	}

	wantCommands := append([]string(nil), manifest.TeardownCmds...)
	exec := &failingCommandExec{
		failures: map[string]error{
			wantCommands[0]: errors.New("boom-nft"),
			wantCommands[1]: errors.New("boom-rule"),
		},
	}

	err := Cleanup(context.Background(), manifest, CleanupDeps{
		CommandExec: exec,
	})
	if err == nil {
		t.Fatalf("Cleanup() error = nil, want aggregated teardown errors")
	}
	if !strings.Contains(err.Error(), "boom-nft") {
		t.Fatalf("Cleanup() error = %q, want nft teardown failure", err.Error())
	}
	if !strings.Contains(err.Error(), "boom-rule") {
		t.Fatalf("Cleanup() error = %q, want ip rule teardown failure", err.Error())
	}

	if len(exec.calls) != len(wantCommands) {
		t.Fatalf("teardown commands attempted = %d, want %d; calls=%#v", len(exec.calls), len(wantCommands), exec.calls)
	}
	for i, call := range exec.calls {
		if call != wantCommands[i] {
			t.Fatalf("teardown command %d = %q, want %q", i, call, wantCommands[i])
		}
	}
}

func TestCleanupUsesOnlyManifestRecordedTeardownCommands(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "run-4")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(stateDir) error = %v", err)
	}

	manifest := Manifest{
		RuntimeID:   "run-4",
		StateRoot:   stateRoot,
		StateDir:    stateDir,
		NetworkMode: "monitor",
		Net: NetResources{
			NetNS:      "box-do-not-touch",
			HostVeth:   "vethhdo-not-touch",
			TableName:  "box_do_not_touch",
			FWMark:     912,
			RouteTable: 10077,
		},
		TeardownCmds: []string{
			"nft delete table inet box_owned",
		},
		ManagedPaths: []ManagedPath{
			{Path: stateDir, Kind: PathKindDir},
		},
	}

	exec := &recordingCommandExec{}
	err := Cleanup(context.Background(), manifest, CleanupDeps{
		CommandExec: exec,
	})
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if len(exec.calls) != 1 || exec.calls[0] != "nft delete table inet box_owned" {
		t.Fatalf("cleanup executed commands = %#v, want only manifest-recorded teardown command", exec.calls)
	}
	for _, call := range exec.calls {
		if strings.Contains(call, "ip link del") || strings.Contains(call, "ip netns del") {
			t.Fatalf("cleanup executed derived network teardown command %q; must use manifest-recorded ownership only", call)
		}
	}
}

type recordingCommandExec struct {
	calls  []string
	onCall func(string)
}

func (r *recordingCommandExec) Run(_ context.Context, name string, args ...string) error {
	call := strings.TrimSpace(strings.Join(append([]string{name}, args...), " "))
	r.calls = append(r.calls, call)
	if r.onCall != nil {
		r.onCall(call)
	}
	return nil
}

func (r *recordingCommandExec) contains(fragment string) bool {
	for _, call := range r.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

type noopCommandExec struct{}

func (noopCommandExec) Run(context.Context, string, ...string) error {
	return nil
}

type noopRunner struct{}

func (noopRunner) Stop() error {
	return nil
}

type failingCommandExec struct {
	calls    []string
	failures map[string]error
}

func (f *failingCommandExec) Run(_ context.Context, name string, args ...string) error {
	call := strings.TrimSpace(strings.Join(append([]string{name}, args...), " "))
	f.calls = append(f.calls, call)
	if err, ok := f.failures[call]; ok {
		return err
	}
	return nil
}

func fixedClock() time.Time {
	return time.Date(2026, 4, 11, 9, 0, 0, 0, time.UTC)
}

func testConfig(networkMode string) config.Config {
	return config.Config{
		Sandbox: config.SandboxConfig{
			Rootfs:       "host-overlay",
			Workdir:      "/workspace",
			Hostname:     "box",
			CommandShell: "/bin/bash -ilc",
		},
		Network: config.NetworkConfig{
			Mode:   networkMode,
			Subnet: "100.96.0.0/24",
			DNS: config.DNSConfig{
				BindAddr: "auto",
				Upstream: []string{"1.1.1.1:53"},
			},
			Envoy: config.EnvoyConfig{
				Enabled:  true,
				Mode:     "peek",
				HTTPPort: 18080,
				TLSPort:  18443,
			},
			TransparentProxy: config.TransparentProxyConfig{
				Enabled:  true,
				Mode:     "peek",
				HTTPPort: 18080,
				TLSPort:  18443,
			},
		},
		Policy: config.PolicyConfig{},
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func mustContain(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("text = %q, want contains %q", text, want)
	}
}

func mustContainCall(t *testing.T, calls []string, want string) {
	t.Helper()
	for _, call := range calls {
		if strings.Contains(call, want) {
			return
		}
	}
	t.Fatalf("calls = %#v, want one containing %q", calls, want)
}

func countCallsContaining(calls []string, fragment string) int {
	count := 0
	for _, call := range calls {
		if strings.Contains(call, fragment) {
			count++
		}
	}
	return count
}
