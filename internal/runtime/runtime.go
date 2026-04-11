package runtime

import (
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
	"gvisor-net/internal/dns"
	"gvisor-net/internal/firewall"
	"gvisor-net/internal/monitor"
	"gvisor-net/internal/netns"
	"gvisor-net/internal/proxy"
	"gvisor-net/internal/rootfs"
)

const (
	defaultStateRoot = "/run/box"
	eventLogName     = "events.log"
	manifestFileName = "manifest.json"
)

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

type DNSServerFactory func(ctx context.Context, req DNSStartRequest) (Runner, error)
type ProxyFactory func(ctx context.Context, req ProxyStartRequest) (Runner, error)

type Deps struct {
	Clock            func() time.Time
	RandomID         func() string
	CommandExec      CommandExec
	DNS              DNSServerFactory
	Proxy            ProxyFactory
	MonitorPreflight MonitorPreflightFunc
}

type DNSStartRequest struct {
	Mode      string
	GatewayIP string
	Config    dns.Config
	OnQuery   func(hostname string)
}

type ProxyStartRequest struct {
	Mode    string
	Config  config.TransparentProxyConfig
	OnEvent func(proxy.Event)
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
	RuntimeID      string              `json:"runtime_id"`
	CreatedAtUTC   string              `json:"created_at_utc"`
	StateRoot      string              `json:"state_root"`
	StateDir       string              `json:"state_dir"`
	ManifestPath   string              `json:"manifest_path"`
	EventLogPath   string              `json:"event_log_path"`
	NetworkMode    string              `json:"network_mode"`
	GatewayIP      string              `json:"gateway_ip"`
	ResolvConf     string              `json:"resolv_conf"`
	Docker         config.DockerConfig `json:"docker"`
	Net            NetResources        `json:"net"`
	StartedRunners []string            `json:"started_runners"`
	TeardownCmds   []string            `json:"teardown_cmds"`
	ManagedPaths   []ManagedPath       `json:"managed_paths"`
}

type NetResources struct {
	NetNS      string `json:"netns"`
	HostVeth   string `json:"host_veth"`
	GuestVeth  string `json:"guest_veth"`
	TableName  string `json:"table_name"`
	FWMark     uint32 `json:"fwmark"`
	RouteTable int    `json:"route_table"`
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

	stateDir := filepath.Join(stateRoot, runtimeID)
	if err := assertNoStateConflict(stateDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create runtime state dir %q: %w", stateDir, err)
	}

	eventLogPath := filepath.Join(stateDir, eventLogName)
	if err := os.WriteFile(eventLogPath, []byte(""), 0o644); err != nil {
		return nil, fmt.Errorf("create event log %q: %w", eventLogPath, err)
	}

	network := strings.TrimSpace(req.Config.Network.Mode)
	gatewayIP, err := gatewayIPFromSubnet(req.Config.Network.Subnet)
	if err != nil {
		return nil, err
	}

	rootfsPlan, err := rootfs.BuildPlan(rootfs.PlanRequest{
		RootfsMode:     req.Config.Sandbox.Rootfs,
		RepoPath:       "",
		Workdir:        req.Config.Sandbox.Workdir,
		NetworkMode:    network,
		GatewayIP:      gatewayIP,
		SandboxHostn:   req.Config.Sandbox.Hostname,
		DockerEnabled:  req.Config.Docker.Enabled,
		DockerDataRoot: req.Config.Docker.DataRoot,
		ExtraRO:        req.Config.Mounts.ExtraRO,
		ExtraRW:        req.Config.Mounts.ExtraRW,
	})
	if err != nil {
		return nil, fmt.Errorf("build rootfs plan: %w", err)
	}

	netResources, err := netns.ResourcesForRuntimeID(runtimeID)
	if err != nil {
		return nil, fmt.Errorf("derive net resources: %w", err)
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
		Docker:         req.Config.Docker,
		Net:            fromNetnsResources(netResources),
		StartedRunners: nil,
		TeardownCmds:   nil,
		ManagedPaths: []ManagedPath{
			{Path: eventLogPath, Kind: PathKindFile},
			{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
		},
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
		rt.monitor = monitor.NewCollector(req.Config.Policy)
		if err := rt.startMonitorResources(ctx, req.Config, deps); err != nil {
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

func (rt *Runtime) startMonitorResources(ctx context.Context, cfg config.Config, deps Deps) error {
	if deps.MonitorPreflight == nil {
		return conflictError(errors.New("monitor preflight conflict/ownership check is required"))
	}
	if err := deps.MonitorPreflight(ctx, MonitorPreflightRequest{
		RuntimeID: rt.Manifest.RuntimeID,
		StateDir:  rt.Manifest.StateDir,
		Network:   cfg.Network.Mode,
		Net:       rt.Manifest.Net,
	}); err != nil {
		return conflictError(fmt.Errorf("monitor preflight: %w", err))
	}

	if deps.DNS != nil {
		onQuery := rt.monitorDNSCallback()
		dnsRunner, err := deps.DNS(ctx, DNSStartRequest{
			Mode:      cfg.Network.Mode,
			GatewayIP: rt.Manifest.GatewayIP,
			Config: dns.Config{
				ListenAddr: cfg.Network.DNS.BindAddr,
				Upstreams:  append([]string(nil), cfg.Network.DNS.Upstream...),
				OnQuery:    onQuery,
			},
			OnQuery: onQuery,
		})
		if err != nil {
			return fmt.Errorf("start dns: %w", err)
		}
		if dnsRunner != nil {
			rt.runners["dns"] = dnsRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "dns")
		}
	}

	dnsPort, err := resolveMonitorDNSPort(cfg.Network.DNS.BindAddr, rt.Manifest.GatewayIP)
	if err != nil {
		return err
	}

	firewallPlan, err := firewall.BuildMonitorPlan(firewall.MonitorPlanInput{
		TableName:  rt.Manifest.Net.TableName,
		HostVeth:   rt.Manifest.Net.HostVeth,
		SubnetCIDR: cfg.Network.Subnet,
		DNSPort:    dnsPort,
		ProxyPort:  cfg.Network.TransparentProxy.HTTPPort,
		FWMark:     rt.Manifest.Net.FWMark,
	})
	if err != nil {
		return fmt.Errorf("build firewall monitor plan: %w", err)
	}
	monitorTeardown := fmt.Sprintf("nft delete table inet %s", rt.Manifest.Net.TableName)
	recordedTeardown, err := runOwnedCommands(ctx, deps.CommandExec, ownedCommandsFromStrings(firewallPlan.Commands, map[int]string{
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

	if cfg.Network.TransparentProxy.Enabled && deps.Proxy != nil {
		onEvent := rt.monitorProxyCallback()
		proxyRunner, err := deps.Proxy(ctx, ProxyStartRequest{
			Mode:    cfg.Network.TransparentProxy.Mode,
			Config:  cfg.Network.TransparentProxy,
			OnEvent: onEvent,
		})
		if err != nil {
			return fmt.Errorf("start proxy: %w", err)
		}
		if proxyRunner != nil {
			rt.runners["proxy"] = proxyRunner
			rt.Manifest.StartedRunners = append(rt.Manifest.StartedRunners, "proxy")
		}
	}

	return nil
}

func (rt *Runtime) monitorDNSCallback() func(hostname string) {
	if rt == nil || rt.monitor == nil {
		return nil
	}
	return func(hostname string) {
		rt.monitor.AddDNS(hostname)
		rt.logRawMonitorEvent(rawMonitorEvent{
			Type:     "dns",
			Hostname: hostname,
		})
	}
}

func (rt *Runtime) monitorProxyCallback() func(proxy.Event) {
	if rt == nil || rt.monitor == nil {
		return nil
	}
	return func(event proxy.Event) {
		hostname := proxyEventHostname(event)
		switch strings.ToLower(strings.TrimSpace(event.Protocol)) {
		case "http":
			rt.monitor.AddHTTP(event.Method, hostname)
		case "tls":
			rt.monitor.AddTLS(hostname)
		}

		rt.logRawMonitorEvent(rawMonitorEvent{
			Type:     "proxy",
			Protocol: event.Protocol,
			Hostname: hostname,
			Method:   event.Method,
			Path:     event.Path,
			Host:     event.Host,
			SNI:      event.SNI,
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

func proxyEventHostname(event proxy.Event) string {
	if hostname := strings.TrimSpace(event.Hostname); hostname != "" {
		return hostname
	}
	if host := strings.TrimSpace(event.Host); host != "" {
		return host
	}
	return strings.TrimSpace(event.SNI)
}

func nowUTC(deps Deps) time.Time {
	if deps.Clock != nil {
		return deps.Clock().UTC()
	}
	return time.Now().UTC()
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

func resolveMonitorDNSPort(bindAddr, gatewayIP string) (int, error) {
	listenAddr, err := dns.ResolveListenAddr(bindAddr, "monitor", gatewayIP)
	if err != nil {
		return 0, err
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return 0, fmt.Errorf("parse monitor dns listen addr %q: %w", listenAddr, err)
	}
	value, err := strconv.Atoi(port)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid monitor dns listen port %q", port)
	}
	return value, nil
}

func generatedFileContent(files []rootfs.GeneratedFile, path string) string {
	for _, file := range files {
		if file.Path == path {
			return file.Content
		}
	}
	return ""
}

func fromNetnsResources(in netns.Resources) NetResources {
	return NetResources{
		NetNS:      in.NetNS,
		HostVeth:   in.HostVeth,
		GuestVeth:  in.GuestVeth,
		TableName:  in.TableName,
		FWMark:     in.FWMark,
		RouteTable: in.RouteTable,
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
			teardown = append(teardown, command.Teardown)
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
	return os.WriteFile(path, content, 0o644)
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
