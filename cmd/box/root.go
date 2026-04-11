package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor-net/internal/config"
	"gvisor-net/internal/dns"
	"gvisor-net/internal/gvisor"
	"gvisor-net/internal/proxy"
	"gvisor-net/internal/rootfs"
	boxruntime "gvisor-net/internal/runtime"

	"github.com/spf13/cobra"
)

const (
	envInitShimPath     = "BOX_INIT_SHIM_PATH"
	defaultInitShimPath = "/usr/local/libexec/box-initshim"
	envDockerEnabled    = "BOX_DOCKER_ENABLED"
	envDockerSocketPath = "BOX_DOCKER_SOCKET_PATH"
	envDockerWait       = "BOX_DOCKER_WAIT_FOR_SOCKET"
	envDockerReady      = "BOX_DOCKER_READY_TIMEOUT"
	defaultNoProxy      = "127.0.0.1,localhost"
)

type ttyState struct {
	Stdin  bool
	Stdout bool
	Stderr bool
}

type runRequest struct {
	ConfigPath   string
	Payload      []string
	ShellCommand string
	InitShimPath string
	TTY          ttyState
}

type executor interface {
	Run(runRequest) error
}

type deps struct {
	executor        executor
	resolveInitShim func() string
	detectTTY       func() ttyState
}

func newRootCommand(d deps) *cobra.Command {
	if d.executor == nil || isNoopExecutor(d.executor) {
		d.executor = runtimeExecutor{}
	}
	if d.resolveInitShim == nil {
		d.resolveInitShim = defaultResolveInitShim
	}
	if d.detectTTY == nil {
		d.detectTTY = defaultTTYDetector
	}

	var configPath string

	root := &cobra.Command{
		Use:   "box",
		Short: "box CLI",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPayload(d, configPath, args)
		},
	}
	root.SilenceUsage = true
	root.PersistentFlags().StringVar(&configPath, "config", "box.yaml", "path to config file")

	run := &cobra.Command{
		Use:   "run",
		Short: "run payload command",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPayload(d, configPath, args)
		},
	}
	root.AddCommand(run)

	return root
}

func runPayload(d deps, configPath string, payload []string) error {
	if len(payload) == 0 {
		return errors.New("payload required after --")
	}

	req := runRequest{
		ConfigPath:   configPath,
		Payload:      payload,
		ShellCommand: shellCommand(payload),
		InitShimPath: d.resolveInitShim(),
		TTY:          d.detectTTY(),
	}
	return d.executor.Run(req)
}

type runtimeExecutor struct{}

func (runtimeExecutor) Run(req runRequest) error {
	ctx := context.Background()

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	cfg, err := config.Load(req.ConfigPath, cwd)
	if err != nil {
		return err
	}
	cfg.Sandbox.CommandShell = commandShellForTTY(cfg.Sandbox.CommandShell, req.TTY)

	deps := boxruntime.Deps{
		CommandExec:      hostCommandExec{},
		DNS:              startDNSRunner,
		MonitorPreflight: monitorPreflight,
		Proxy:            startHTTPProxyRunner,
	}

	rt, err := boxruntime.Run(ctx, boxruntime.Request{Config: cfg}, deps)
	if err != nil {
		return err
	}

	rootfsPlan, err := rootfs.BuildPlan(rootfs.PlanRequest{
		RootfsMode:       cfg.Sandbox.Rootfs,
		RepoPath:         cwd,
		Workdir:          cfg.Sandbox.Workdir,
		NetworkMode:      cfg.Network.Mode,
		GatewayIP:        rt.Manifest.GatewayIP,
		SandboxHostn:     cfg.Sandbox.Hostname,
		DockerEnabled:    cfg.Docker.Enabled,
		DockerDataRoot:   cfg.Docker.DataRoot,
		DockerSocketPath: cfg.Docker.SocketPath,
		DockerHTTPProxy:  proxyURL(rt.Manifest.GatewayIP, cfg.Network.TransparentProxy.HTTPPort),
		DockerHTTPSProxy: proxyURL(rt.Manifest.GatewayIP, cfg.Network.TransparentProxy.HTTPPort),
		DockerNoProxy:    defaultNoProxy,
		ExtraRO:          cfg.Mounts.ExtraRO,
		ExtraRW:          cfg.Mounts.ExtraRW,
	})
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build rootfs plan: %w", err)
	}

	bundleDir := filepath.Join(rt.Manifest.StateDir, "bundle")
	if _, err := rootfs.Apply(rootfs.ApplyRequest{
		Plan:           rootfsPlan,
		BundleDir:      bundleDir,
		InitShimPath:   req.InitShimPath,
		ExecutablePath: req.InitShimPath,
	}); err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("apply rootfs plan: %w", err)
	}

	spec, err := gvisor.BuildSandboxSpec(gvisor.BuildSpecRequest{
		Config:               cfg,
		Workdir:              cfg.Sandbox.Workdir,
		Payload:              req.ShellCommand,
		ExtraEnv:             sandboxProxyAndDockerEnv(rt.Manifest.GatewayIP, cfg),
		RootfsPlan:           rootfsPlan,
		NetworkNamespacePath: filepath.Join("/run/netns", rt.Manifest.Net.NetNS),
	})
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build sandbox spec: %w", err)
	}
	if err := writeBundleSpec(bundleDir, spec); err != nil {
		_ = rt.Cleanup(ctx, deps)
		return err
	}

	payloadErr := gvisor.Runner{}.Run(gvisor.RunRequest{
		BundleDir:   bundleDir,
		ContainerID: rt.Manifest.RuntimeID,
		NetNS:       rt.Manifest.Net.NetNS,
	})
	cleanupErr := rt.Cleanup(ctx, deps)
	return errors.Join(payloadErr, cleanupErr)
}

type hostCommandExec struct{}

func (hostCommandExec) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type preflightCommandRunner func(ctx context.Context, name string, args ...string) (string, error)

func monitorPreflight(ctx context.Context, req boxruntime.MonitorPreflightRequest) error {
	return checkMonitorOwnership(ctx, req, runPreflightCommand)
}

func checkMonitorOwnership(ctx context.Context, req boxruntime.MonitorPreflightRequest, run preflightCommandRunner) error {
	tableName := strings.TrimSpace(req.Net.TableName)
	if tableName != "" {
		exists, err := nftTableExists(ctx, run, tableName)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if exists {
			return errors.Join(boxruntime.ErrResourceConflict, fmt.Errorf("nft table %q already exists", tableName))
		}
	}

	if req.Net.RouteTable > 0 {
		hasEntries, err := routeTableInUse(ctx, run, req.Net.RouteTable)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if hasEntries {
			return errors.Join(boxruntime.ErrResourceConflict, fmt.Errorf("ip route table %d already has entries", req.Net.RouteTable))
		}
	}

	if req.Net.FWMark != 0 && req.Net.RouteTable > 0 {
		policyExists, err := policyRuleExists(ctx, run, req.Net.FWMark, req.Net.RouteTable)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if policyExists {
			return errors.Join(boxruntime.ErrResourceConflict, fmt.Errorf("ip policy rule for fwmark=%d lookup=%d already exists", req.Net.FWMark, req.Net.RouteTable))
		}
	}

	netnsName := strings.TrimSpace(req.Net.NetNS)
	if netnsName != "" {
		exists, err := netnsExists(ctx, run, netnsName)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if exists {
			return errors.Join(boxruntime.ErrResourceConflict, fmt.Errorf("network namespace %q already exists", netnsName))
		}
	}

	hostVeth := strings.TrimSpace(req.Net.HostVeth)
	if hostVeth != "" {
		exists, err := linkExists(ctx, run, hostVeth)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if exists {
			return errors.Join(boxruntime.ErrResourceConflict, fmt.Errorf("host veth %q already exists", hostVeth))
		}
	}

	return nil
}

func nftTableExists(ctx context.Context, run preflightCommandRunner, tableName string) (bool, error) {
	out, err := run(ctx, "nft", "list", "table", "inet", tableName)
	if err == nil {
		return true, nil
	}
	if outputLooksLikeMissingResource(out) {
		return false, nil
	}
	return false, fmt.Errorf("query nft table %q: %w: %s", tableName, err, strings.TrimSpace(out))
}

func routeTableInUse(ctx context.Context, run preflightCommandRunner, routeTable int) (bool, error) {
	out, err := run(ctx, "ip", "-o", "route", "show", "table", strconv.Itoa(routeTable))
	if err != nil {
		if outputLooksLikeMissingResource(out) {
			return false, nil
		}
		return false, fmt.Errorf("query ip route table %d: %w: %s", routeTable, err, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out) != "", nil
}

func policyRuleExists(ctx context.Context, run preflightCommandRunner, fwmark uint32, routeTable int) (bool, error) {
	out, err := run(ctx, "ip", "-o", "rule", "show")
	if err != nil {
		return false, fmt.Errorf("query ip rules: %w: %s", err, strings.TrimSpace(out))
	}

	lookupNeedle := fmt.Sprintf("lookup %d", routeTable)
	fwmarkHexNeedle := fmt.Sprintf("fwmark 0x%x", fwmark)
	fwmarkDecNeedle := fmt.Sprintf("fwmark %d", fwmark)
	for _, line := range strings.Split(out, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" {
			continue
		}
		if strings.Contains(clean, lookupNeedle) &&
			(strings.Contains(clean, fwmarkHexNeedle) || strings.Contains(clean, fwmarkDecNeedle)) {
			return true, nil
		}
	}

	return false, nil
}

func netnsExists(ctx context.Context, run preflightCommandRunner, name string) (bool, error) {
	out, err := run(ctx, "ip", "netns", "list")
	if err != nil {
		return false, fmt.Errorf("query network namespaces: %w: %s", err, strings.TrimSpace(out))
	}

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == name {
			return true, nil
		}
	}
	return false, nil
}

func linkExists(ctx context.Context, run preflightCommandRunner, name string) (bool, error) {
	out, err := run(ctx, "ip", "link", "show", name)
	if err == nil {
		return true, nil
	}
	if outputLooksLikeMissingResource(out) {
		return false, nil
	}
	return false, fmt.Errorf("query network link %q: %w: %s", name, err, strings.TrimSpace(out))
}

func outputLooksLikeMissingResource(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "fib table does not exist")
}

func runPreflightCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	return combined.String(), err
}

func isNoopExecutor(execImpl executor) bool {
	switch execImpl.(type) {
	case noopExecutor, *noopExecutor:
		return true
	default:
		return false
	}
}

func shellCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, shellQuote(arg))
	}
	return strings.Join(escaped, " ")
}

var shellSafePattern = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if shellSafePattern.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func defaultResolveInitShim() string {
	return resolveInitShimPath(os.Getenv, os.Executable, fileExists)
}

func resolveInitShimPath(getenv func(string) string, executable func() (string, error), exists func(string) bool) string {
	if fromEnv := strings.TrimSpace(getenv(envInitShimPath)); fromEnv != "" {
		return fromEnv
	}
	exePath, err := executable()
	if err == nil && exePath != "" {
		sibling := filepath.Join(filepath.Dir(exePath), "box-initshim")
		if exists(sibling) {
			return sibling
		}
	}
	return defaultInitShimPath
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func defaultTTYDetector() ttyState {
	return detectTTY(os.Stdin, os.Stdout, os.Stderr, isTerminalFD)
}

func detectTTY(stdin, stdout, stderr *os.File, isTerminal func(fd uintptr) bool) ttyState {
	state := ttyState{}
	if stdin != nil {
		state.Stdin = isTerminal(stdin.Fd())
	}
	if stdout != nil {
		state.Stdout = isTerminal(stdout.Fd())
	}
	if stderr != nil {
		state.Stderr = isTerminal(stderr.Fd())
	}
	return state
}

func isTerminalFD(fd uintptr) bool {
	file := os.NewFile(fd, "tty-probe")
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func writeBundleSpec(bundleDir string, spec gvisor.Spec) error {
	content, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal gvisor spec: %w", err)
	}
	content = append(content, '\n')
	configPath := filepath.Join(bundleDir, "config.json")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		return fmt.Errorf("write bundle config %q: %w", configPath, err)
	}
	return nil
}

func commandShellForTTY(commandShell string, tty ttyState) string {
	if tty.Stdin || tty.Stdout || tty.Stderr {
		return commandShell
	}

	fields := strings.Fields(commandShell)
	for i, field := range fields {
		if !strings.HasPrefix(field, "-") || len(field) == 1 {
			continue
		}
		trimmed := strings.ReplaceAll(field[1:], "i", "")
		if trimmed == field[1:] {
			continue
		}
		if trimmed == "" {
			fields = append(fields[:i], fields[i+1:]...)
		} else {
			fields[i] = "-" + trimmed
		}
		return strings.Join(fields, " ")
	}
	return commandShell
}

func startDNSRunner(ctx context.Context, req boxruntime.DNSStartRequest) (boxruntime.Runner, error) {
	server, err := dns.Start(ctx, req.Config, dns.Deps{
		Mode:      req.Mode,
		GatewayIP: req.GatewayIP,
	})
	if err != nil {
		return nil, err
	}
	return stopFunc(server.Close), nil
}

func startHTTPProxyRunner(ctx context.Context, req boxruntime.ProxyStartRequest) (boxruntime.Runner, error) {
	if !req.Config.Enabled {
		return nil, nil
	}

	server, err := proxy.StartHTTP(ctx, proxy.ProxyConfig{
		ListenAddr: net.JoinHostPort("", strconv.Itoa(req.Config.HTTPPort)),
	})
	if err != nil {
		return nil, err
	}
	return stopFunc(server.Close), nil
}

func sandboxProxyAndDockerEnv(gatewayIP string, cfg config.Config) []string {
	proxy := proxyURL(gatewayIP, cfg.Network.TransparentProxy.HTTPPort)
	env := []string{
		"HTTP_PROXY=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"NO_PROXY=" + defaultNoProxy,
	}
	if !cfg.Docker.Enabled {
		return env
	}

	socketPath := strings.TrimSpace(cfg.Docker.SocketPath)
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	return append(env,
		envDockerEnabled+"=1",
		envDockerSocketPath+"="+socketPath,
		envDockerWait+"="+boolString(cfg.Docker.WaitForSocket),
		envDockerReady+"="+cfg.Docker.ReadyTimeout.String(),
	)
}

func proxyURL(host string, port int) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

type stopFunc func() error

func (f stopFunc) Stop() error {
	return f()
}
