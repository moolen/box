package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor-net/internal/config"
	"gvisor-net/internal/netns"
)

func TestRunCreatesStateDirAndEventLog(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("deny-all")

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

func TestMonitorModeRewritesResolvConfToGatewayIP(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Network.DNS.Upstream = []string{"1.1.1.1:53"}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-monitor-a" },
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		DNS: func(context.Context, DNSStartRequest) (Runner, error) {
			return noopRunner{}, nil
		},
		CommandExec: noopCommandExec{},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(rt.Manifest.ResolvConf, "nameserver 100.96.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, want nameserver gateway IP", rt.Manifest.ResolvConf)
	}
	if strings.Contains(rt.Manifest.ResolvConf, "nameserver 127.0.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, must not use localhost in monitor mode", rt.Manifest.ResolvConf)
	}
}

func TestMonitorModeStartsDNSAndFirewallWithScopedResources(t *testing.T) {
	t.Parallel()

	cfg := testConfig("monitor")
	cfg.Network.DNS.Upstream = []string{"1.1.1.1:53"}

	var dnsReq DNSStartRequest
	var dnsCalled bool
	exec := &recordingCommandExec{}

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-monitor-b" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			return nil
		},
		DNS: func(_ context.Context, req DNSStartRequest) (Runner, error) {
			dnsCalled = true
			dnsReq = req
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !dnsCalled {
		t.Fatalf("DNS factory was not called in monitor mode")
	}
	if dnsReq.Mode != "monitor" {
		t.Fatalf("DNS request mode = %q, want %q", dnsReq.Mode, "monitor")
	}
	if dnsReq.GatewayIP != "100.96.0.1" {
		t.Fatalf("DNS request gateway ip = %q, want %q", dnsReq.GatewayIP, "100.96.0.1")
	}

	resources, err := netns.ResourcesForRuntimeID("runtime-monitor-b")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error = %v", err)
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

func TestNonMonitorModeDoesNotForceGatewayResolvConf(t *testing.T) {
	t.Parallel()

	cfg := testConfig("enforce-dns")

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

	if !strings.Contains(rt.Manifest.ResolvConf, "nameserver 127.0.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, want localhost nameserver outside monitor mode", rt.Manifest.ResolvConf)
	}
	if strings.Contains(rt.Manifest.ResolvConf, "nameserver 100.96.0.1") {
		t.Fatalf("Manifest.ResolvConf = %q, must not force gateway nameserver outside monitor mode", rt.Manifest.ResolvConf)
	}
}

func TestDockerSettingsPropagateIntoRuntimeState(t *testing.T) {
	t.Parallel()

	cfg := testConfig("deny-all")
	cfg.Docker = config.DockerConfig{
		Enabled:                     true,
		DataRoot:                    "/sandbox/docker",
		SocketPath:                  "/sandbox/docker.sock",
		WaitForSocket:               true,
		ReadyTimeout:                15 * time.Second,
		HostNetworkNestedContainers: true,
	}

	rt, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: t.TempDir(),
	}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-d" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rt.Manifest.Docker != cfg.Docker {
		t.Fatalf("Manifest.Docker = %#v, want %#v", rt.Manifest.Docker, cfg.Docker)
	}
}

func TestRejectsMITMBeforeMutatingHostState(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("monitor")
	cfg.Network.TransparentProxy.Mode = "mitm"

	exec := &recordingCommandExec{}
	dnsCalled := false
	proxyCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-blocked" },
		CommandExec: exec,
		DNS: func(context.Context, DNSStartRequest) (Runner, error) {
			dnsCalled = true
			return noopRunner{}, nil
		},
		Proxy: func(context.Context, ProxyStartRequest) (Runner, error) {
			proxyCalled = true
			return noopRunner{}, nil
		},
	})
	if err == nil {
		t.Fatalf("Run() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "network.transparent_proxy.mode=mitm") {
		t.Fatalf("Run() error = %q, want transparent proxy mitm rejection", err.Error())
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "runtime-blocked")); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state dir should not exist on early validation failure; stat err=%v", statErr)
	}
	if dnsCalled {
		t.Fatalf("DNS factory was called before runtime rejected unsupported mode")
	}
	if proxyCalled {
		t.Fatalf("Proxy factory was called before runtime rejected unsupported mode")
	}
	if len(exec.calls) != 0 {
		t.Fatalf("command exec calls = %#v, want none before rejection", exec.calls)
	}
}

func TestMonitorPreflightConflictPreventsMonitorMutationAndTeardown(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("monitor")

	exec := &recordingCommandExec{}
	dnsCalled := false
	proxyCalled := false

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
		DNS: func(context.Context, DNSStartRequest) (Runner, error) {
			dnsCalled = true
			return noopRunner{}, nil
		},
		Proxy: func(context.Context, ProxyStartRequest) (Runner, error) {
			proxyCalled = true
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
	if dnsCalled {
		t.Fatalf("DNS factory was called despite monitor preflight conflict")
	}
	if proxyCalled {
		t.Fatalf("Proxy factory was called despite monitor preflight conflict")
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "runtime-preflight-conflict")); !os.IsNotExist(statErr) {
		t.Fatalf("state dir should be cleaned up on preflight conflict; stat err=%v", statErr)
	}
}

func TestMonitorModeWithoutPreflightFailsClosedBeforeMutation(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	cfg := testConfig("monitor")

	exec := &recordingCommandExec{}
	dnsCalled := false
	proxyCalled := false

	_, err := Run(context.Background(), Request{
		Config:    cfg,
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-missing-preflight" },
		CommandExec: exec,
		DNS: func(context.Context, DNSStartRequest) (Runner, error) {
			dnsCalled = true
			return noopRunner{}, nil
		},
		Proxy: func(context.Context, ProxyStartRequest) (Runner, error) {
			proxyCalled = true
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
	if dnsCalled {
		t.Fatalf("DNS factory was called despite missing monitor preflight")
	}
	if proxyCalled {
		t.Fatalf("Proxy factory was called despite missing monitor preflight")
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

	cfg := testConfig("deny-all")
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
		StartedRunners: []string{"dns", "proxy", "runsc"},
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
	if order[0] != "stop:runsc" || order[1] != "stop:proxy" || order[2] != "stop:dns" {
		t.Fatalf("runner stop order = %#v, want reverse-start order runsc->proxy->dns", order)
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
			Subnet: "100.96.0.0/30",
			DNS: config.DNSConfig{
				BindAddr: "auto",
				Upstream: []string{"1.1.1.1:53"},
			},
			TransparentProxy: config.TransparentProxyConfig{
				Enabled:  true,
				Mode:     "peek",
				HTTPPort: 18080,
				TLSPort:  18443,
			},
		},
	}
}
