package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor-net/internal/config"
	"gvisor-net/internal/firewall"
	"gvisor-net/internal/monitor"
	"gvisor-net/internal/netns"
	"gvisor-net/internal/pki"
	"gvisor-net/internal/policyd"
	"gvisor-net/internal/rootfs"
)

const (
	defaultStateRoot            = "/run/box"
	eventLogName                = "events.log"
	manifestFileName            = "manifest.json"
	caDirName                   = "ca"
	caCertFileName              = "root-ca.pem"
	caKeyFileName               = "root-ca-key.pem"
	upstreamTrustBundleFileName = "upstream-trust-bundle.crt"
	envoyDirName                = "envoy"
	bootstrapName               = "bootstrap.yaml"
)

var systemTrustBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
	"/usr/share/ncat/ca-bundle.crt",
}

var ErrResourceConflict = errors.New("resource conflict")

type Request struct {
	Config    config.Config
	StateRoot string
}

type CommandExec interface {
	Run(ctx context.Context, name string, args ...string) error
}

type Runner interface {
	Stop() error
}

type PolicyServiceFactory func(ctx context.Context, req PolicyServiceStartRequest) (Runner, error)
type EnvoyFactory func(ctx context.Context, req EnvoyStartRequest) (Runner, error)

type Deps struct {
	Clock                func() time.Time
	RandomID             func() string
	CommandExec          CommandExec
	AllocateNetResources func(ctx context.Context, runtimeID string, subnetPool string) (netns.Resources, error)
	StartPolicyService   PolicyServiceFactory
	StartEnvoy           EnvoyFactory
	MonitorPreflight     MonitorPreflightFunc
}

type PolicyServiceStartRequest struct {
	RuntimeID         string
	Mode              string
	GatewayIP         string
	ListenAddr        string
	DNSListenAddr     string
	ProxyListenAddr   string
	ProxyUpstreamAddr string
	Rules             []config.NetworkPolicyRule
	DNSUpstream       []string
	OnEvent           func(policyd.Event)
}

type EnvoyStartRequest struct {
	RuntimeID                  string
	MonitorMode                bool
	GatewayIP                  string
	InternalExplicitPort       int
	TransparentPort            int
	DNSPort                    int
	DNSUpstream                []string
	BootstrapPath              string
	LogPath                    string
	PolicyListenAddr           string
	TransparentTLSCertificates []TransparentTLSCertificate
	UpstreamTrustBundlePath    string
}

type MonitorPreflightRequest struct {
	RuntimeID string
	StateDir  string
	Network   string
	Net       NetResources
}

type MonitorPreflightFunc func(ctx context.Context, req MonitorPreflightRequest) error

type Runtime struct {
	Manifest Manifest
	runners  map[string]Runner
	monitor  *monitor.Collector
	eventMu  sync.Mutex
}

type Manifest struct {
	RuntimeID          string        `json:"runtime_id"`
	CreatedAtUTC       string        `json:"created_at_utc"`
	StateRoot          string        `json:"state_root"`
	StateDir           string        `json:"state_dir"`
	ManifestPath       string        `json:"manifest_path"`
	EventLogPath       string        `json:"event_log_path"`
	WorkdirMountSource string        `json:"workdir_mount_source,omitempty"`
	NetworkMode        string        `json:"network_mode"`
	GatewayIP          string        `json:"gateway_ip"`
	ResolvConf         string        `json:"resolv_conf"`
	Envoy              EnvoyRuntime  `json:"envoy"`
	CA                 CARuntime     `json:"ca"`
	Net                NetResources  `json:"net"`
	StartedRunners     []string      `json:"started_runners"`
	TeardownCmds       []string      `json:"teardown_cmds"`
	ManagedPaths       []ManagedPath `json:"managed_paths"`
}

type EnvoyRuntime struct {
	ExplicitPort         int    `json:"explicit_port"`
	InternalExplicitPort int    `json:"internal_explicit_port"`
	TransparentPort      int    `json:"transparent_port"`
	DNSPort              int    `json:"dns_port"`
	BootstrapPath        string `json:"bootstrap_path"`
}

type CARuntime struct {
	CertPath                   string                      `json:"cert_path"`
	KeyPath                    string                      `json:"key_path"`
	SandboxCertPath            string                      `json:"sandbox_cert_path"`
	UpstreamTrustBundlePath    string                      `json:"upstream_trust_bundle_path,omitempty"`
	TransparentTLSCertificates []TransparentTLSCertificate `json:"transparent_tls_certificates,omitempty"`
}

type TransparentTLSCertificate struct {
	ServerNames []string `json:"server_names"`
	CertPath    string   `json:"cert_path"`
	KeyPath     string   `json:"key_path"`
}

type NetResources struct {
	NetNS      string `json:"netns"`
	HostVeth   string `json:"host_veth"`
	GuestVeth  string `json:"guest_veth"`
	TableName  string `json:"table_name"`
	FWMark     uint32 `json:"fwmark"`
	RouteTable int    `json:"route_table"`
	SubnetCIDR string `json:"subnet_cidr,omitempty"`
}

type PathKind string

const (
	PathKindFile PathKind = "file"
	PathKindDir  PathKind = "dir"
)

type ManagedPath struct {
	Path string   `json:"path"`
	Kind PathKind `json:"kind"`
}

func Run(ctx context.Context, req Request, deps Deps) (_ *Runtime, runErr error) {
	if err := config.ValidateRuntime(req.Config); err != nil {
		return nil, err
	}

	runtimeID := strings.TrimSpace(newRuntimeID(deps))
	if runtimeID == "" {
		return nil, errors.New("runtime id is required")
	}

	stateRoot := strings.TrimSpace(req.StateRoot)
	if stateRoot == "" {
		stateRoot = defaultStateRoot
	}
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime state root %q: %w", req.StateRoot, err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state root %q: %w", stateRoot, err)
	}
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		return nil, fmt.Errorf("chmod runtime state root %q: %w", stateRoot, err)
	}
	if err := cleanupOrphanedRuntimes(ctx, stateRoot, deps.CommandExec); err != nil {
		return nil, err
	}

	stateDir := filepath.Join(stateRoot, runtimeID)
	if err := assertNoStateConflict(stateDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state dir %q: %w", stateDir, err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod runtime state dir %q: %w", stateDir, err)
	}

	eventLogPath := filepath.Join(stateDir, eventLogName)
	if err := os.WriteFile(eventLogPath, []byte(""), 0o600); err != nil {
		return nil, fmt.Errorf("create event log %q: %w", eventLogPath, err)
	}

	network := strings.TrimSpace(req.Config.Network.Mode)
	allocateNetResources := deps.AllocateNetResources
	if allocateNetResources == nil {
		allocateNetResources = func(ctx context.Context, runtimeID string, subnetPool string) (netns.Resources, error) {
			return netns.AllocateResources(ctx, runtimeID, subnetPool, nil)
		}
	}
	netResources, err := allocateNetResources(ctx, runtimeID, req.Config.Network.Subnet)
	if err != nil {
		return nil, fmt.Errorf("allocate net resources: %w", err)
	}
	gatewayIP, err := gatewayIPFromSubnet(netResources.SubnetCIDR)
	if err != nil {
		return nil, err
	}
	runtimeCfg := req.Config
	runtimeCfg.Network.Subnet = netResources.SubnetCIDR

	envoyRuntime, caRuntime, caCertPEM, err := prepareManagedNetworkAssets(network, stateDir, runtimeID, runtimeCfg.Network.Policy)
	if err != nil {
		return nil, err
	}
	trustedCAPEM := BuildSandboxTrustBundlePEM(caCertPEM)

	rootfsPlan, err := rootfs.BuildPlan(rootfs.PlanRequest{
		RootfsMode:        runtimeCfg.Sandbox.Rootfs,
		RepoPath:          "",
		Workdir:           runtimeCfg.Sandbox.Workdir,
		NetworkMode:       network,
		GatewayIP:         gatewayIP,
		SandboxHostn:      runtimeCfg.Sandbox.Hostname,
		ExtraRO:           runtimeCfg.Mounts.ExtraRO,
		ExtraRW:           runtimeCfg.Mounts.ExtraRW,
		RuntimeCACertPEM:  caCertPEM,
		TrustedCACertPEM:  trustedCAPEM,
		TrustedCACertPath: caRuntime.SandboxCertPath,
	})
	if err != nil {
		return nil, fmt.Errorf("build rootfs plan: %w", err)
	}

	managedPaths := []ManagedPath{
		{Path: eventLogPath, Kind: PathKindFile},
		{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
		{Path: stateDir, Kind: PathKindDir},
	}
	if strings.TrimSpace(caRuntime.CertPath) != "" {
		managedPaths = append(managedPaths, ManagedPath{Path: caRuntime.CertPath, Kind: PathKindFile})
	}
	if strings.TrimSpace(caRuntime.KeyPath) != "" {
		managedPaths = append(managedPaths, ManagedPath{Path: caRuntime.KeyPath, Kind: PathKindFile})
	}

	manifest := Manifest{
		RuntimeID:      runtimeID,
		CreatedAtUTC:   nowUTC(deps).Format(time.RFC3339Nano),
		StateRoot:      stateRoot,
		StateDir:       stateDir,
		ManifestPath:   filepath.Join(stateDir, manifestFileName),
		EventLogPath:   eventLogPath,
		NetworkMode:    network,
		GatewayIP:      gatewayIP,
		ResolvConf:     generatedFileContent(rootfsPlan.GeneratedFiles, "/etc/resolv.conf"),
		Envoy:          envoyRuntime,
		CA:             caRuntime,
		Net:            fromNetnsResources(netResources),
		StartedRunners: nil,
		TeardownCmds:   nil,
		ManagedPaths:   managedPaths,
	}

	rt := &Runtime{
		Manifest: manifest,
		runners:  make(map[string]Runner),
	}

	defer func() {
		if runErr == nil {
			return
		}
		_ = rt.Cleanup(ctx, deps)
	}()

	if strings.EqualFold(network, "monitor") {
		rt.monitor = monitor.NewCollector()
	}
	if usesManagedNetworkPolicy(network) && deps.CommandExec != nil {
		if err := monitorPreflightCheck(ctx, rt.Manifest, runtimeCfg, deps); err != nil {
			return nil, err
		}
	}
	if err := prepareWorkdirOverlay(ctx, runtimeCfg, &rt.Manifest, deps.CommandExec); err != nil {
		return nil, err
	}

	if err := rt.startNetNSResources(ctx, runtimeCfg, deps); err != nil {
		return nil, err
	}

	if strings.EqualFold(network, "monitor") {
		if err := rt.startMonitorResources(ctx, runtimeCfg, deps); err != nil {
			return nil, err
		}
	} else if strings.EqualFold(network, "enforce") {
		if err := rt.startEnforceResources(ctx, runtimeCfg, deps); err != nil {
			return nil, err
		}
	}

	if err := writeManifest(rt.Manifest.ManifestPath, rt.Manifest); err != nil {
		return nil, fmt.Errorf("persist manifest: %w", err)
	}

	_ = appendEvent(rt.Manifest.EventLogPath, fmt.Sprintf("runtime %s started", rt.Manifest.RuntimeID))
	return rt, nil
}

func (rt *Runtime) Cleanup(ctx context.Context, deps Deps) error {
	if rt == nil {
		return nil
	}

	return Cleanup(ctx, rt.Manifest, CleanupDeps{
		CommandExec: deps.CommandExec,
		StopRunner: func(name string) error {
			runner, ok := rt.runners[name]
			if !ok || runner == nil {
				return nil
			}
			return runner.Stop()
		},
	})
}

func (rt *Runtime) MonitorSummary() string {
	if rt == nil || rt.monitor == nil {
		return ""
	}
	return monitor.RenderSummary(rt.monitor.Snapshot())
}

func (rt *Runtime) PayloadNetNS() string {
	if rt == nil || !strings.EqualFold(rt.Manifest.NetworkMode, "monitor") {
		return ""
	}
	return strings.TrimSpace(rt.Manifest.Net.NetNS)
}

func (rt *Runtime) RuntimeManifest() Manifest {
	if rt == nil {
		return Manifest{}
	}
	return rt.Manifest
}

func SandboxEnv(manifest Manifest) []string {
	var env []string
	if gatewayIP := strings.TrimSpace(manifest.GatewayIP); gatewayIP != "" && manifest.Envoy.ExplicitPort > 0 {
		proxy := "http://" + net.JoinHostPort(gatewayIP, strconv.Itoa(manifest.Envoy.ExplicitPort))
		env = append(env,
			"HTTP_PROXY="+proxy,
			"HTTPS_PROXY="+proxy,
			"WS_PROXY="+proxy,
			"WSS_PROXY="+proxy,
			"http_proxy="+proxy,
			"https_proxy="+proxy,
			"ws_proxy="+proxy,
			"wss_proxy="+proxy,
			"NO_PROXY=127.0.0.1,localhost",
			"no_proxy=127.0.0.1,localhost",
		)
	}
	if caPath := strings.TrimSpace(manifest.CA.SandboxCertPath); caPath != "" {
		env = append(env,
			"SSL_CERT_FILE="+caPath,
			"CURL_CA_BUNDLE="+caPath,
			"REQUESTS_CA_BUNDLE="+caPath,
			"NODE_EXTRA_CA_CERTS="+caPath,
		)
	}
	return env
}

func (rt *Runtime) startMonitorResources(ctx context.Context, cfg config.Config, deps Deps) error {
	policyListenAddr, err := allocateLoopbackTCPAddr()
	if err != nil {
		return fmt.Errorf("allocate policy service addr: %w", err)
	}
	dnsListenAddr, err := allocateLoopbackUDPAddr()
	if err != nil {
		return fmt.Errorf("allocate policyd dns addr: %w", err)
	}
	dnsUpstreamAddr, err := loopbackAddrForPort(dnsListenAddr)
	if err != nil {
		return fmt.Errorf("derive policyd dns upstream addr: %w", err)
	}
	if deps.StartPolicyService != nil {
		policyRunner, err := deps.StartPolicyService(ctx, PolicyServiceStartRequest{
			RuntimeID:         rt.Manifest.RuntimeID,
			Mode:              cfg.Network.Mode,
			GatewayIP:         rt.Manifest.GatewayIP,
			ListenAddr:        policyListenAddr,
			DNSListenAddr:     dnsListenAddr,
			ProxyListenAddr:   wildcardAddrForPort(rt.Manifest.Envoy.ExplicitPort),
			ProxyUpstreamAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(rt.Manifest.Envoy.InternalExplicitPort)),
			Rules:             append([]config.NetworkPolicyRule(nil), cfg.Network.Policy...),
			DNSUpstream:       append([]string(nil), cfg.Network.DNS.Upstream...),
			OnEvent:           rt.monitorPolicyEventCallback(),
		})
		if err != nil {
			return fmt.Errorf("start policyd: %w", err)
		}
		if policyRunner != nil {
			rt.runners["policyd"] = policyRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "policyd")
		}
	}
	if deps.StartEnvoy != nil {
		envoyRunner, err := deps.StartEnvoy(ctx, EnvoyStartRequest{
			RuntimeID:                  rt.Manifest.RuntimeID,
			MonitorMode:                strings.EqualFold(cfg.Network.Mode, "monitor"),
			GatewayIP:                  rt.Manifest.GatewayIP,
			InternalExplicitPort:       rt.Manifest.Envoy.InternalExplicitPort,
			TransparentPort:            rt.Manifest.Envoy.TransparentPort,
			DNSPort:                    rt.Manifest.Envoy.DNSPort,
			DNSUpstream:                []string{dnsUpstreamAddr},
			BootstrapPath:              rt.Manifest.Envoy.BootstrapPath,
			LogPath:                    filepath.Join(rt.Manifest.StateDir, "envoy.log"),
			PolicyListenAddr:           policyListenAddr,
			TransparentTLSCertificates: append([]TransparentTLSCertificate(nil), rt.Manifest.CA.TransparentTLSCertificates...),
			UpstreamTrustBundlePath:    rt.Manifest.CA.UpstreamTrustBundlePath,
		})
		if err != nil {
			return fmt.Errorf("start envoy: %w", err)
		}
		if envoyRunner != nil {
			rt.runners["envoy"] = envoyRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "envoy")
		}
	}

	firewallPlan, err := firewall.BuildMonitorPlan(firewall.MonitorPlanInput{
		TableName:    rt.Manifest.Net.TableName,
		HostVeth:     rt.Manifest.Net.HostVeth,
		SubnetCIDR:   cfg.Network.Subnet,
		GatewayIP:    rt.Manifest.GatewayIP,
		DNSPort:      rt.Manifest.Envoy.DNSPort,
		ExplicitPort: rt.Manifest.Envoy.ExplicitPort,
		ProxyPort:    rt.Manifest.Envoy.TransparentPort,
		FWMark:       rt.Manifest.Net.FWMark,
	})
	if err != nil {
		return fmt.Errorf("build firewall monitor plan: %w", err)
	}
	monitorTeardown := fmt.Sprintf("nft delete table inet %s", rt.Manifest.Net.TableName)
	var recordedTeardown []string
	recordedTeardown, err = runOwnedCommands(ctx, deps.CommandExec, ownedCommandsFromStrings(firewallPlan.Commands, map[int]string{
		0: monitorTeardown,
	}))
	rt.Manifest.TeardownCmds = append(rt.Manifest.TeardownCmds, recordedTeardown...)
	if err != nil {
		return fmt.Errorf("apply firewall plan: %w", err)
	}

	routingPlan, err := firewall.BuildPolicyRoutingPlan(rt.Manifest.Net.FWMark, rt.Manifest.Net.RouteTable)
	if err != nil {
		return fmt.Errorf("build policy routing plan: %w", err)
	}
	recordedTeardown, err = runOwnedCommands(ctx, deps.CommandExec, ownedCommandsFromStrings(routingPlan, map[int]string{
		0: fmt.Sprintf("ip rule del fwmark %d lookup %d", rt.Manifest.Net.FWMark, rt.Manifest.Net.RouteTable),
		1: fmt.Sprintf("ip route del local 0.0.0.0/0 dev lo table %d", rt.Manifest.Net.RouteTable),
	}))
	rt.Manifest.TeardownCmds = append(rt.Manifest.TeardownCmds, recordedTeardown...)
	if err != nil {
		return fmt.Errorf("apply policy routing plan: %w", err)
	}

	return nil
}

func (rt *Runtime) startEnforceResources(ctx context.Context, cfg config.Config, deps Deps) error {
	policyListenAddr, err := allocateLoopbackTCPAddr()
	if err != nil {
		return fmt.Errorf("allocate policy service addr: %w", err)
	}
	dnsListenAddr, err := allocateLoopbackUDPAddr()
	if err != nil {
		return fmt.Errorf("allocate policyd dns addr: %w", err)
	}
	dnsUpstreamAddr, err := loopbackAddrForPort(dnsListenAddr)
	if err != nil {
		return fmt.Errorf("derive policyd dns upstream addr: %w", err)
	}
	if deps.StartPolicyService != nil {
		policyRunner, err := deps.StartPolicyService(ctx, PolicyServiceStartRequest{
			RuntimeID:         rt.Manifest.RuntimeID,
			Mode:              cfg.Network.Mode,
			GatewayIP:         rt.Manifest.GatewayIP,
			ListenAddr:        policyListenAddr,
			DNSListenAddr:     dnsListenAddr,
			ProxyListenAddr:   wildcardAddrForPort(rt.Manifest.Envoy.ExplicitPort),
			ProxyUpstreamAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(rt.Manifest.Envoy.InternalExplicitPort)),
			Rules:             append([]config.NetworkPolicyRule(nil), cfg.Network.Policy...),
			DNSUpstream:       append([]string(nil), cfg.Network.DNS.Upstream...),
			OnEvent:           rt.monitorPolicyEventCallback(),
		})
		if err != nil {
			return fmt.Errorf("start policyd: %w", err)
		}
		if policyRunner != nil {
			rt.runners["policyd"] = policyRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "policyd")
		}
	}
	if deps.StartEnvoy != nil {
		envoyRunner, err := deps.StartEnvoy(ctx, EnvoyStartRequest{
			RuntimeID:                  rt.Manifest.RuntimeID,
			MonitorMode:                strings.EqualFold(cfg.Network.Mode, "monitor"),
			GatewayIP:                  rt.Manifest.GatewayIP,
			InternalExplicitPort:       rt.Manifest.Envoy.InternalExplicitPort,
			TransparentPort:            rt.Manifest.Envoy.TransparentPort,
			DNSPort:                    rt.Manifest.Envoy.DNSPort,
			DNSUpstream:                []string{dnsUpstreamAddr},
			BootstrapPath:              rt.Manifest.Envoy.BootstrapPath,
			LogPath:                    filepath.Join(rt.Manifest.StateDir, "envoy.log"),
			PolicyListenAddr:           policyListenAddr,
			TransparentTLSCertificates: append([]TransparentTLSCertificate(nil), rt.Manifest.CA.TransparentTLSCertificates...),
			UpstreamTrustBundlePath:    rt.Manifest.CA.UpstreamTrustBundlePath,
		})
		if err != nil {
			return fmt.Errorf("start envoy: %w", err)
		}
		if envoyRunner != nil {
			rt.runners["envoy"] = envoyRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "envoy")
		}
	}

	if err := ensureIPv4Forwarding(ctx, deps.CommandExec, &rt.Manifest); err != nil {
		return err
	}

	firewallPlan, err := firewall.BuildEnforcePlan(firewall.EnforcePlanInput{
		TableName:       rt.Manifest.Net.TableName,
		HostVeth:        rt.Manifest.Net.HostVeth,
		SubnetCIDR:      cfg.Network.Subnet,
		GatewayIP:       rt.Manifest.GatewayIP,
		DNSPort:         rt.Manifest.Envoy.DNSPort,
		ExplicitPort:    rt.Manifest.Envoy.ExplicitPort,
		TransparentPort: rt.Manifest.Envoy.TransparentPort,
	})
	if err != nil {
		return fmt.Errorf("build firewall enforce plan: %w", err)
	}

	recordedTeardown, err := runOwnedCommands(ctx, deps.CommandExec, ownedCommandsFromStrings(firewallPlan.Commands, map[int]string{
		0: fmt.Sprintf("nft delete table inet %s", rt.Manifest.Net.TableName),
	}))
	rt.Manifest.TeardownCmds = append(rt.Manifest.TeardownCmds, recordedTeardown...)
	if err != nil {
		return fmt.Errorf("apply firewall enforce plan: %w", err)
	}

	return nil
}

func (rt *Runtime) startNetNSResources(ctx context.Context, cfg config.Config, deps Deps) error {
	setupPlan, err := netns.BuildSetupPlan(netns.Resources{
		NetNS:      rt.Manifest.Net.NetNS,
		HostVeth:   rt.Manifest.Net.HostVeth,
		GuestVeth:  rt.Manifest.Net.GuestVeth,
		TableName:  rt.Manifest.Net.TableName,
		FWMark:     rt.Manifest.Net.FWMark,
		RouteTable: rt.Manifest.Net.RouteTable,
		SubnetCIDR: rt.Manifest.Net.SubnetCIDR,
	})
	if err != nil {
		return fmt.Errorf("build netns setup plan: %w", err)
	}

	rt.Manifest.GatewayIP = setupPlan.GatewayIP
	commands := []ownedCommand{
		{Apply: setupPlan.Commands[0], Teardown: setupPlan.Teardown[1]},
		{Apply: setupPlan.Commands[1], Teardown: setupPlan.Teardown[0]},
	}
	for _, command := range setupPlan.Commands[2:] {
		commands = append(commands, ownedCommand{Apply: command})
	}

	recordedTeardown, err := runOwnedCommands(ctx, deps.CommandExec, commands)
	rt.Manifest.TeardownCmds = append(rt.Manifest.TeardownCmds, recordedTeardown...)
	if err != nil {
		return fmt.Errorf("apply netns setup plan: %w", err)
	}
	return nil
}

func monitorPreflightCheck(ctx context.Context, manifest Manifest, cfg config.Config, deps Deps) error {
	if deps.MonitorPreflight == nil {
		return conflictError(errors.New("monitor preflight conflict/ownership check is required"))
	}
	if err := deps.MonitorPreflight(ctx, MonitorPreflightRequest{
		RuntimeID: manifest.RuntimeID,
		StateDir:  manifest.StateDir,
		Network:   cfg.Network.Mode,
		Net:       manifest.Net,
	}); err != nil {
		return conflictError(fmt.Errorf("monitor preflight: %w", err))
	}
	return nil
}

func (rt *Runtime) monitorPolicyEventCallback() func(policyd.Event) {
	if rt == nil || rt.monitor == nil {
		return nil
	}
	return func(event policyd.Event) {
		hostname := strings.TrimSpace(event.Hostname)
		verdict := monitorVerdict(event.Verdict)
		switch strings.ToLower(strings.TrimSpace(event.Type)) {
		case "dns":
			rt.monitor.AddDNS(hostname, verdict)
		case "http":
			rt.monitor.AddHTTP(event.Method, hostname, verdict)
		case "tls":
			rt.monitor.AddTLS(hostname, verdict)
		}

		rt.logRawMonitorEvent(rawMonitorEvent{
			Type:     event.Type,
			Protocol: event.Protocol,
			Hostname: hostname,
			Method:   event.Method,
			Path:     event.Path,
			Host:     event.Host,
			SNI:      event.SNI,
			Verdict:  string(event.Verdict),
			Reason:   event.Reason,
		})
	}
}

type rawMonitorEvent struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func (rt *Runtime) logRawMonitorEvent(event rawMonitorEvent) {
	if rt == nil {
		return
	}

	line, err := json.Marshal(event)
	if err != nil {
		return
	}

	rt.eventMu.Lock()
	defer rt.eventMu.Unlock()
	_ = appendEvent(rt.Manifest.EventLogPath, string(line))
}

func nowUTC(deps Deps) time.Time {
	if deps.Clock != nil {
		return deps.Clock().UTC()
	}
	return time.Now().UTC()
}

func monitorVerdict(verdict policyd.Verdict) monitor.Verdict {
	switch verdict {
	case policyd.VerdictAllow:
		return monitor.VerdictAllow
	case policyd.VerdictWouldAllow:
		return monitor.VerdictWouldAllow
	case policyd.VerdictWouldBlock:
		return monitor.VerdictWouldBlock
	default:
		return monitor.VerdictDeny
	}
}

func allocateLoopbackTCPAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

func allocateLoopbackUDPAddr() (string, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

func allocateWildcardUDPAddr() (string, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return "", err
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

func loopbackAddrForPort(addr string) (string, error) {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", err
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func wildcardAddrForPort(port int) string {
	if port <= 0 {
		return ""
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
}

func newRuntimeID(deps Deps) string {
	if deps.RandomID != nil {
		return deps.RandomID()
	}
	return fmt.Sprintf("run-%d", nowUTC(deps).UnixNano())
}

func assertNoStateConflict(stateDir string) error {
	_, err := os.Stat(stateDir)
	if err == nil {
		return fmt.Errorf("%w: runtime state dir %q already exists", ErrResourceConflict, stateDir)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat runtime state dir %q: %w", stateDir, err)
	}
	return nil
}

func gatewayIPFromSubnet(subnet string) (string, error) {
	trimmed := strings.TrimSpace(subnet)
	if trimmed == "" {
		return "", errors.New("network subnet is required")
	}

	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse subnet %q: %w", trimmed, err)
	}

	addr := prefix.Masked().Addr()
	if !addr.Is4() {
		return "", fmt.Errorf("subnet %q must be ipv4", trimmed)
	}

	gateway := addr.Next()
	if !prefix.Contains(gateway) {
		return "", fmt.Errorf("subnet %q has no usable gateway ip", trimmed)
	}
	return gateway.String(), nil
}

func usesManagedNetworkPolicy(mode string) bool {
	mode = strings.TrimSpace(mode)
	return strings.EqualFold(mode, "monitor") || strings.EqualFold(mode, "enforce")
}

func ensureIPv4Forwarding(ctx context.Context, execer CommandExec, manifest *Manifest) error {
	if execer == nil || manifest == nil {
		return nil
	}

	currentBytes, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_forward: %w", err)
	}
	current := strings.TrimSpace(string(currentBytes))
	if current == "1" {
		return nil
	}

	if err := execer.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable net.ipv4.ip_forward: %w", err)
	}
	manifest.TeardownCmds = append([]string{
		fmt.Sprintf("sysctl -w net.ipv4.ip_forward=%s", current),
	}, manifest.TeardownCmds...)
	return nil
}

func generatedFileContent(files []rootfs.GeneratedFile, path string) string {
	for _, file := range files {
		if file.Path == path {
			return file.Content
		}
	}
	return ""
}

func prepareManagedNetworkAssets(networkMode, stateDir, runtimeID string, rules []config.NetworkPolicyRule) (EnvoyRuntime, CARuntime, string, error) {
	if !usesManagedNetworkPolicy(networkMode) {
		return EnvoyRuntime{}, CARuntime{}, "", nil
	}

	envoyRuntime, err := allocateEnvoyRuntime(stateDir)
	if err != nil {
		return EnvoyRuntime{}, CARuntime{}, "", fmt.Errorf("allocate envoy runtime ports: %w", err)
	}
	caRuntime, certPEM, err := writeRuntimeCAAssets(stateDir, runtimeID, rules)
	if err != nil {
		return EnvoyRuntime{}, CARuntime{}, "", fmt.Errorf("prepare runtime ca assets: %w", err)
	}
	return envoyRuntime, caRuntime, certPEM, nil
}

func allocateEnvoyRuntime(stateDir string) (EnvoyRuntime, error) {
	envoyDir := filepath.Join(stateDir, envoyDirName)
	if err := os.MkdirAll(envoyDir, 0o700); err != nil {
		return EnvoyRuntime{}, fmt.Errorf("create envoy dir %q: %w", envoyDir, err)
	}

	explicit, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return EnvoyRuntime{}, err
	}
	defer explicit.Close()

	internalExplicit, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return EnvoyRuntime{}, err
	}
	defer internalExplicit.Close()

	transparent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return EnvoyRuntime{}, err
	}
	defer transparent.Close()

	dnsListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return EnvoyRuntime{}, err
	}
	defer dnsListener.Close()

	return EnvoyRuntime{
		ExplicitPort:         listenerPort(explicit.Addr()),
		InternalExplicitPort: listenerPort(internalExplicit.Addr()),
		TransparentPort:      listenerPort(transparent.Addr()),
		DNSPort:              listenerPort(dnsListener.LocalAddr()),
		BootstrapPath:        filepath.Join(envoyDir, bootstrapName),
	}, nil
}

func writeRuntimeCAAssets(stateDir, runtimeID string, rules []config.NetworkPolicyRule) (CARuntime, string, error) {
	caDir := filepath.Join(stateDir, caDirName)
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return CARuntime{}, "", fmt.Errorf("create ca dir %q: %w", caDir, err)
	}

	runtimeCA, err := pki.NewRuntimeCA(runtimeID)
	if err != nil {
		return CARuntime{}, "", err
	}

	certPath := filepath.Join(caDir, caCertFileName)
	if err := os.WriteFile(certPath, runtimeCA.RootCertPEM, 0o644); err != nil {
		return CARuntime{}, "", fmt.Errorf("write ca cert %q: %w", certPath, err)
	}
	keyPath := filepath.Join(caDir, caKeyFileName)
	if err := os.WriteFile(keyPath, runtimeCA.RootKeyPEM, 0o600); err != nil {
		return CARuntime{}, "", fmt.Errorf("write ca key %q: %w", keyPath, err)
	}
	upstreamTrustBundlePath := filepath.Join(caDir, upstreamTrustBundleFileName)
	if trustBundle := buildSystemTrustBundlePEM(); strings.TrimSpace(trustBundle) != "" {
		if err := os.WriteFile(upstreamTrustBundlePath, []byte(trustBundle), 0o644); err != nil {
			return CARuntime{}, "", fmt.Errorf("write upstream trust bundle %q: %w", upstreamTrustBundlePath, err)
		}
	} else {
		upstreamTrustBundlePath = ""
	}
	transparentTLSCertificates, err := writeTransparentTLSCertificates(filepath.Join(stateDir, envoyDirName, "tls"), runtimeCA, rules)
	if err != nil {
		return CARuntime{}, "", err
	}

	return CARuntime{
		CertPath:                   certPath,
		KeyPath:                    keyPath,
		SandboxCertPath:            rootfs.TrustedCABundlePath,
		UpstreamTrustBundlePath:    upstreamTrustBundlePath,
		TransparentTLSCertificates: transparentTLSCertificates,
	}, string(runtimeCA.RootCertPEM), nil
}

func BuildSandboxTrustBundlePEM(runtimeCAPEM string) string {
	runtimeCAPEM = strings.TrimSpace(runtimeCAPEM)
	if runtimeCAPEM == "" {
		return ""
	}

	bundle := bytes.NewBufferString(buildSystemTrustBundlePEM())
	bundle.WriteString(runtimeCAPEM)
	if !strings.HasSuffix(runtimeCAPEM, "\n") {
		bundle.WriteByte('\n')
	}
	return bundle.String()
}

func buildSystemTrustBundlePEM() string {
	var bundle bytes.Buffer
	for _, path := range systemTrustBundlePaths {
		content, err := os.ReadFile(path)
		if err != nil || len(bytes.TrimSpace(content)) == 0 {
			continue
		}
		bundle.Write(content)
		if last := content[len(content)-1]; last != '\n' {
			bundle.WriteByte('\n')
		}
	}
	return bundle.String()
}

func writeTransparentTLSCertificates(dir string, runtimeCA *pki.RuntimeCA, rules []config.NetworkPolicyRule) ([]TransparentTLSCertificate, error) {
	if runtimeCA == nil {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var certificates []TransparentTLSCertificate
	for _, rule := range rules {
		host := normalizeTransparentTLSServerName(rule.Hostname)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}

		certPEM, keyPEM, err := runtimeCA.IssueLeaf(pki.LeafRequest{DNSName: host})
		if err != nil {
			return nil, fmt.Errorf("issue transparent tls certificate for %q: %w", host, err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create transparent tls dir %q: %w", dir, err)
		}
		base := sanitizeTransparentTLSFilename(host)
		certPath := filepath.Join(dir, base+".crt")
		keyPath := filepath.Join(dir, base+".key")
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, fmt.Errorf("write transparent tls cert %q: %w", certPath, err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, fmt.Errorf("write transparent tls key %q: %w", keyPath, err)
		}
		certificates = append(certificates, TransparentTLSCertificate{
			ServerNames: []string{host},
			CertPath:    certPath,
			KeyPath:     keyPath,
		})
	}
	return certificates, nil
}

func normalizeTransparentTLSServerName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}

func sanitizeTransparentTLSFilename(host string) string {
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		return "transparent-tls"
	}
	return name
}

func buildSandboxTrustBundlePEM(runtimeCAPEM string) string {
	return BuildSandboxTrustBundlePEM(runtimeCAPEM)
}

func listenerPort(addr net.Addr) int {
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.Port
	case *net.UDPAddr:
		return value.Port
	default:
		return 0
	}
}

func fromNetnsResources(in netns.Resources) NetResources {
	return NetResources{
		NetNS:      in.NetNS,
		HostVeth:   in.HostVeth,
		GuestVeth:  in.GuestVeth,
		TableName:  in.TableName,
		FWMark:     in.FWMark,
		RouteTable: in.RouteTable,
		SubnetCIDR: in.SubnetCIDR,
	}
}

func runCommandStrings(ctx context.Context, execer CommandExec, commands []string) error {
	if execer == nil {
		return nil
	}
	for _, command := range commands {
		fields := strings.Fields(command)
		if len(fields) == 0 {
			continue
		}
		if err := execer.Run(ctx, fields[0], fields[1:]...); err != nil {
			return fmt.Errorf("run %q: %w", command, err)
		}
	}
	return nil
}

type ownedCommand struct {
	Apply    string
	Teardown string
}

func runOwnedCommands(ctx context.Context, execer CommandExec, commands []ownedCommand) ([]string, error) {
	if execer == nil {
		return nil, nil
	}

	var teardown []string
	for _, command := range commands {
		if strings.TrimSpace(command.Apply) == "" {
			continue
		}

		fields := strings.Fields(command.Apply)
		if len(fields) == 0 {
			continue
		}
		if err := execer.Run(ctx, fields[0], fields[1:]...); err != nil {
			return teardown, fmt.Errorf("run %q: %w", command.Apply, err)
		}
		if strings.TrimSpace(command.Teardown) != "" {
			teardown = append([]string{command.Teardown}, teardown...)
		}
	}
	return teardown, nil
}

func ownedCommandsFromStrings(commands []string, teardownByIndex map[int]string) []ownedCommand {
	out := make([]ownedCommand, 0, len(commands))
	for idx, command := range commands {
		out = append(out, ownedCommand{
			Apply:    command,
			Teardown: teardownByIndex[idx],
		})
	}
	return out
}

func conflictError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrResourceConflict) {
		return err
	}
	return errors.Join(ErrResourceConflict, err)
}

func writeManifest(path string, manifest Manifest) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	return os.WriteFile(path, content, 0o600)
}

func appendEvent(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}
