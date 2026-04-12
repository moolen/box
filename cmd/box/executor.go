package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"gvisor-net/internal/config"
	"gvisor-net/internal/dns"
	"gvisor-net/internal/gvisor"
	"gvisor-net/internal/proxy"
	"gvisor-net/internal/rootfs"
	boxruntime "gvisor-net/internal/runtime"
)

const (
	ipTransparent       = 19
	ipv6Transparent     = 75
	envDockerEnabled    = "BOX_DOCKER_ENABLED"
	envDockerConfig     = "DOCKER_CONFIG"
	envDockerSocketPath = "BOX_DOCKER_SOCKET_PATH"
	envDockerWait       = "BOX_DOCKER_WAIT_FOR_SOCKET"
	envDockerReady      = "BOX_DOCKER_READY_TIMEOUT"
	dockerConfigDir     = "/etc/docker"
	defaultNoProxy      = "127.0.0.1,localhost"
	soOriginalDst       = 80
)

type runtimeHandle interface {
	Cleanup(context.Context, boxruntime.Deps) error
	MonitorSummary() string
	PayloadNetNS() string
	RuntimeManifest() boxruntime.Manifest
}

type runtimeExecutor struct {
	stderr           io.Writer
	getwd            func() (string, error)
	loadConfig       func(path, cwd string) (config.Config, error)
	startRuntime     func(ctx context.Context, cfg config.Config, deps boxruntime.Deps) (runtimeHandle, error)
	buildRootfsPlan  func(rootfs.PlanRequest) (rootfs.Plan, error)
	applyRootfs      func(rootfs.ApplyRequest) (rootfs.ApplyResult, error)
	buildSandboxSpec func(gvisor.BuildSpecRequest) (gvisor.Spec, error)
	writeBundleSpec  func(string, gvisor.Spec) error
	runSandbox       func(gvisor.RunRequest) error
}

func (e runtimeExecutor) Run(req runRequest) error {
	ctx := context.Background()

	getwd := e.getwd
	if getwd == nil {
		getwd = os.Getwd
	}

	loadConfig := e.loadConfig
	if loadConfig == nil {
		loadConfig = config.Load
	}

	startRuntime := e.startRuntime
	if startRuntime == nil {
		startRuntime = func(ctx context.Context, cfg config.Config, deps boxruntime.Deps) (runtimeHandle, error) {
			return boxruntime.Run(ctx, boxruntime.Request{Config: cfg}, deps)
		}
	}

	buildRootfsPlan := e.buildRootfsPlan
	if buildRootfsPlan == nil {
		buildRootfsPlan = rootfs.BuildPlan
	}

	applyRootfs := e.applyRootfs
	if applyRootfs == nil {
		applyRootfs = rootfs.Apply
	}

	buildSandboxSpec := e.buildSandboxSpec
	if buildSandboxSpec == nil {
		buildSandboxSpec = gvisor.BuildSandboxSpec
	}

	writeBundleSpec := e.writeBundleSpec
	if writeBundleSpec == nil {
		writeBundleSpec = writeBundleSpecFile
	}

	runSandbox := e.runSandbox
	if runSandbox == nil {
		runSandbox = gvisor.Runner{}.Run
	}

	stderr := e.stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	cwd, err := getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	cfg, err := loadConfig(req.ConfigPath, cwd)
	if err != nil {
		return err
	}
	cfg.Sandbox.CommandShell = commandShellForTTY(cfg.Sandbox.CommandShell, req.TTY)

	deps := boxruntime.Deps{
		CommandExec:      hostCommandExec{},
		DNS:              startDNSRunner,
		Proxy:            startTransparentProxy,
		MonitorPreflight: monitorPreflight,
	}

	rt, err := startRuntime(ctx, cfg, deps)
	if err != nil {
		return err
	}

	manifest := rt.RuntimeManifest()
	repoPath := cwd
	if strings.TrimSpace(manifest.WorkdirMountSource) != "" {
		repoPath = strings.TrimSpace(manifest.WorkdirMountSource)
	}
	rootfsPlan, err := buildRootfsPlan(rootfs.PlanRequest{
		RootfsMode:       cfg.Sandbox.Rootfs,
		RepoPath:         repoPath,
		Workdir:          cfg.Sandbox.Workdir,
		NetworkMode:      cfg.Network.Mode,
		GatewayIP:        manifest.GatewayIP,
		SandboxHostn:     cfg.Sandbox.Hostname,
		DockerEnabled:    cfg.Docker.Enabled,
		DockerDataRoot:   cfg.Docker.DataRoot,
		DockerSocketPath: cfg.Docker.SocketPath,
		DockerHTTPProxy:  dockerProxyValue(manifest.GatewayIP, cfg),
		DockerHTTPSProxy: dockerProxyValue(manifest.GatewayIP, cfg),
		DockerNoProxy:    dockerNoProxyValue(cfg),
		ExtraRO:          cfg.Mounts.ExtraRO,
		ExtraRW:          cfg.Mounts.ExtraRW,
	})
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build rootfs plan: %w", err)
	}

	bundleDir := filepath.Join(manifest.StateDir, "bundle")
	if _, err := applyRootfs(rootfs.ApplyRequest{
		Plan:           rootfsPlan,
		BundleDir:      bundleDir,
		InitShimPath:   req.InitShimPath,
		ExecutablePath: req.InitShimPath,
	}); err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("apply rootfs plan: %w", err)
	}

	spec, err := buildSandboxSpec(gvisor.BuildSpecRequest{
		Config:               cfg,
		Workdir:              cfg.Sandbox.Workdir,
		Payload:              req.ShellCommand,
		HostEnv:              os.Environ(),
		ExtraEnv:             sandboxProxyAndDockerEnv(manifest.GatewayIP, cfg),
		RootfsPlan:           rootfsPlan,
		NetworkNamespacePath: filepath.Join("/run/netns", manifest.Net.NetNS),
	})
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build sandbox spec: %w", err)
	}
	if err := writeBundleSpec(bundleDir, spec); err != nil {
		_ = rt.Cleanup(ctx, deps)
		return err
	}

	payloadErr := runSandbox(gvisor.RunRequest{
		BundleDir:     bundleDir,
		ContainerID:   manifest.RuntimeID,
		NetNS:         manifest.Net.NetNS,
		DockerEnabled: cfg.Docker.Enabled,
	})
	cleanupErr := rt.Cleanup(ctx, deps)
	summaryErr := writeMonitorSummary(stderr, rt.MonitorSummary())
	return errors.Join(payloadErr, cleanupErr, summaryErr)
}

type hostCommandExec struct{}

func (hostCommandExec) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func writeMonitorSummary(stderr io.Writer, summary string) error {
	if stderr == nil || strings.TrimSpace(summary) == "" {
		return nil
	}
	_, err := io.WriteString(stderr, summary)
	return err
}

func startDNSRunner(ctx context.Context, req boxruntime.DNSStartRequest) (boxruntime.Runner, error) {
	cfg := req.Config
	if cfg.OnQuery == nil {
		cfg.OnQuery = req.OnQuery
	}
	if cfg.AllowQuery == nil {
		cfg.AllowQuery = req.AllowQuery
	}
	if cfg.OnResolved == nil {
		cfg.OnResolved = req.OnResolved
	}

	server, err := dns.Start(ctx, cfg, dns.Deps{
		Mode:      req.Mode,
		GatewayIP: req.GatewayIP,
	})
	if err != nil {
		return nil, err
	}
	return stopFunc(server.Close), nil
}

type proxyFactoryDeps struct {
	listen          func(network, address string) (net.Listener, error)
	startHTTP       func(context.Context, proxy.ProxyConfig) (*proxy.Server, error)
	startTLS        func(context.Context, proxy.ProxyConfig) (*proxy.Server, error)
	resolveUpstream func(net.Conn) (string, error)
}

func startTransparentProxy(ctx context.Context, req boxruntime.ProxyStartRequest) (boxruntime.Runner, error) {
	return startTransparentProxyWithDeps(ctx, req, proxyFactoryDeps{
		listen: transparentListen,
	})
}

func startTransparentProxyWithDeps(ctx context.Context, req boxruntime.ProxyStartRequest, deps proxyFactoryDeps) (boxruntime.Runner, error) {
	if deps.listen == nil {
		deps.listen = net.Listen
	}
	if deps.startHTTP == nil {
		deps.startHTTP = proxy.StartHTTP
	}
	if deps.startTLS == nil {
		deps.startTLS = proxy.StartTLS
	}
	if deps.resolveUpstream == nil {
		deps.resolveUpstream = resolveOriginalDst
	}

	onEvent := req.OnEvent

	httpListener, tlsListener, err := proxy.TransparentListenerFactory(req.Config, deps.listen)
	if err != nil {
		return nil, err
	}

	httpServer, err := deps.startHTTP(ctx, proxy.ProxyConfig{
		Listen:          consumeListener(httpListener),
		ResolveUpstream: deps.resolveUpstream,
		AllowTarget:     req.AllowTarget,
		OnEvent:         onEvent,
	})
	if err != nil {
		_ = httpListener.Close()
		_ = tlsListener.Close()
		return nil, err
	}

	tlsServer, err := deps.startTLS(ctx, proxy.ProxyConfig{
		Listen:          consumeListener(tlsListener),
		ResolveUpstream: deps.resolveUpstream,
		AllowTarget:     req.AllowTarget,
		OnEvent:         onEvent,
	})
	if err != nil {
		_ = httpServer.Close()
		_ = tlsListener.Close()
		return nil, err
	}

	return proxyRunner{
		http: httpServer,
		tls:  tlsServer,
	}, nil
}

type proxyRunner struct {
	http *proxy.Server
	tls  *proxy.Server
}

func (r proxyRunner) Stop() error {
	return errors.Join(closeProxyServer(r.tls), closeProxyServer(r.http))
}

func closeProxyServer(server *proxy.Server) error {
	if server == nil {
		return nil
	}
	return server.Close()
}

func consumeListener(listener net.Listener) func(network, address string) (net.Listener, error) {
	used := false
	return func(string, string) (net.Listener, error) {
		if used {
			return nil, errors.New("listener already consumed")
		}
		used = true
		return listener, nil
	}
}

func transparentListen(network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.Control = func(_, _ string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = errors.Join(
				setSockoptBestEffort(int(fd), syscall.SOL_IP, ipTransparent, 1),
				setSockoptBestEffort(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1),
			)
		}); err != nil {
			return err
		}
		return controlErr
	}
	return lc.Listen(context.Background(), network, address)
}

func setSockoptBestEffort(fd int, level int, opt int, value int) error {
	if err := syscall.SetsockoptInt(fd, level, opt, value); err != nil && !errors.Is(err, syscall.ENOPROTOOPT) {
		return err
	}
	return nil
}

func resolveOriginalDst(conn net.Conn) (string, error) {
	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return "", errors.New("connection does not expose syscall conn")
	}

	rawConn, err := sysconn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("get syscall conn: %w", err)
	}

	var (
		addr       *net.TCPAddr
		controlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		addr, controlErr = originalDstFromFD(int(fd), conn.LocalAddr())
	}); err != nil {
		return "", fmt.Errorf("control original dst fd: %w", err)
	}
	if controlErr != nil {
		return "", controlErr
	}
	return addr.String(), nil
}

func originalDstFromFD(fd int, localAddr net.Addr) (*net.TCPAddr, error) {
	if tcpAddr, ok := localAddr.(*net.TCPAddr); ok && tcpAddr.IP.To4() == nil {
		return originalDstIPv6(fd)
	}
	return originalDstIPv4(fd)
}

func originalDstIPv4(fd int) (*net.TCPAddr, error) {
	var raw syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(raw))
	if errno := getSockoptRaw(fd, syscall.IPPROTO_IP, soOriginalDst, unsafe.Pointer(&raw), unsafe.Pointer(&size)); errno != 0 {
		return nil, fmt.Errorf("get ipv4 original dst: %w", errno)
	}
	return tcpAddrFromSockaddrIPv4(raw), nil
}

func originalDstIPv6(fd int) (*net.TCPAddr, error) {
	var raw syscall.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(raw))
	if errno := getSockoptRaw(fd, syscall.IPPROTO_IPV6, soOriginalDst, unsafe.Pointer(&raw), unsafe.Pointer(&size)); errno != 0 {
		return nil, fmt.Errorf("get ipv6 original dst: %w", errno)
	}
	return tcpAddrFromSockaddrIPv6(raw), nil
}

func tcpAddrFromSockaddrIPv4(raw syscall.RawSockaddrInet4) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(raw.Addr[:]),
		Port: decodeSockaddrPort(raw.Port),
	}
}

func tcpAddrFromSockaddrIPv6(raw syscall.RawSockaddrInet6) *net.TCPAddr {
	addr := &net.TCPAddr{
		IP:   net.IP(raw.Addr[:]),
		Port: decodeSockaddrPort(raw.Port),
	}
	if raw.Scope_id != 0 {
		addr.Zone = strconv.FormatUint(uint64(raw.Scope_id), 10)
	}
	return addr
}

func decodeSockaddrPort(port uint16) int {
	return int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&port))[:]))
}

func getSockoptRaw(fd int, level int, opt int, value unsafe.Pointer, size unsafe.Pointer) syscall.Errno {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(value),
		uintptr(size),
		0,
	)
	return errno
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

func writeBundleSpecFile(bundleDir string, spec gvisor.Spec) error {
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

func sandboxProxyAndDockerEnv(gatewayIP string, cfg config.Config) []string {
	var env []string
	if modeUsesProxy(cfg) {
		proxy := proxyURL(gatewayIP, cfg.Network.TransparentProxy.HTTPPort)
		env = append(env,
			"HTTP_PROXY="+proxy,
			"HTTPS_PROXY="+proxy,
			"NO_PROXY="+defaultNoProxy,
		)
	}
	if !cfg.Docker.Enabled {
		return env
	}

	if dockerUsesProxy(cfg) {
		env = append(env, envDockerConfig+"="+dockerConfigDir)
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

func modeUsesProxy(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.Network.Mode), "monitor") && cfg.Network.TransparentProxy.Enabled
}

func dockerProxyValue(gatewayIP string, cfg config.Config) string {
	if !dockerUsesProxy(cfg) {
		return ""
	}
	return proxyURL(gatewayIP, cfg.Network.TransparentProxy.HTTPPort)
}

func dockerNoProxyValue(cfg config.Config) string {
	if !dockerUsesProxy(cfg) {
		return ""
	}
	return defaultNoProxy
}

func dockerUsesProxy(cfg config.Config) bool {
	return modeUsesProxy(cfg) || (strings.EqualFold(strings.TrimSpace(cfg.Network.Mode), "enforce") &&
		cfg.Docker.Enabled &&
		cfg.Docker.HostNetworkNestedContainers)
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
