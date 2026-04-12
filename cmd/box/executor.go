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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gvisor-net/internal/config"
	"gvisor-net/internal/dns"
	"gvisor-net/internal/gvisor"
	"gvisor-net/internal/launcher"
	"gvisor-net/internal/proxy"
	"gvisor-net/internal/rootfs"
	boxruntime "gvisor-net/internal/runtime"
)

const (
	ipTransparent         = 19
	ipv6Transparent       = 75
	envBuildKitdFlags     = "BUILDKITD_FLAGS"
	envBuildKitHost       = "BUILDKIT_HOST"
	envBuildKitHTTPProxy  = "BOX_BUILDKIT_HTTP_PROXY"
	envBuildKitHTTPSProxy = "BOX_BUILDKIT_HTTPS_PROXY"
	envBuildKitNoProxy    = "BOX_BUILDKIT_NO_PROXY"
	envBuildKitHome       = "BOX_BUILDKIT_HOME"
	buildkitPathDir       = "/box/bin"
	envDockerEnabled      = "BOX_DOCKER_ENABLED"
	envDockerMode         = "BOX_DOCKER_MODE"
	envDockerUser         = "BOX_DOCKER_USER"
	envDockerUID          = "BOX_DOCKER_UID"
	envDockerGID          = "BOX_DOCKER_GID"
	envDockerHome         = "BOX_DOCKER_HOME"
	envDockerRuntimeDir   = "BOX_DOCKER_RUNTIME_DIR"
	envDockerDataRoot     = "BOX_DOCKER_DATA_ROOT"
	envDockerConfig       = "DOCKER_CONFIG"
	envDockerHost         = "DOCKER_HOST"
	envDockerSocketPath   = "BOX_DOCKER_SOCKET_PATH"
	envDockerWait         = "BOX_DOCKER_WAIT_FOR_SOCKET"
	envDockerReady        = "BOX_DOCKER_READY_TIMEOUT"
	dockerConfigDir       = "/etc/docker"
	defaultNoProxy        = "127.0.0.1,localhost"
	soOriginalDst         = 80
)

type runtimeHandle interface {
	Cleanup(context.Context, boxruntime.Deps) error
	MonitorSummary() string
	PayloadNetNS() string
	RuntimeManifest() boxruntime.Manifest
}

type runtimeExecutor struct {
	stderr                     io.Writer
	getwd                      func() (string, error)
	loadConfig                 func(path, cwd string) (config.Config, error)
	startRuntime               func(ctx context.Context, cfg config.Config, deps boxruntime.Deps) (runtimeHandle, error)
	buildRootfsPlan            func(rootfs.PlanRequest) (rootfs.Plan, error)
	applyRootfs                func(rootfs.ApplyRequest) (rootfs.ApplyResult, error)
	buildSandboxSpec           func(gvisor.BuildSpecRequest) (gvisor.Spec, error)
	writeBundleSpec            func(string, gvisor.Spec) error
	runSandbox                 func(gvisor.RunRequest) error
	startSandboxBuildKitDaemon func(boxruntime.Manifest, int, int, config.Config) (*managedBuildKitDaemon, error)
	stopSandboxBuildKitDaemon  func(*managedBuildKitDaemon) error
	ensureRootlessRuntimeDir   func(int, int) error
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
	startSandboxBuildKitDaemon := e.startSandboxBuildKitDaemon
	if startSandboxBuildKitDaemon == nil {
		startSandboxBuildKitDaemon = startSandboxManagedBuildKitDaemon
	}
	stopSandboxBuildKitDaemon := e.stopSandboxBuildKitDaemon
	if stopSandboxBuildKitDaemon == nil {
		stopSandboxBuildKitDaemon = stopManagedBuildKitDaemon
	}
	ensureRootlessRuntimeDirFn := e.ensureRootlessRuntimeDir
	if ensureRootlessRuntimeDirFn == nil {
		ensureRootlessRuntimeDirFn = ensureRootlessRuntimeDir
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

	callerUID := 0
	callerGID := 0
	if cfg.BuildKit.Enabled {
		callerUID, callerGID, err = rootlessCallerFromEnv(os.Getenv)
		if err != nil {
			return err
		}
		if err := ensureRootlessRuntimeDirFn(callerUID, callerGID); err != nil {
			return fmt.Errorf("prepare rootless runtime dir: %w", err)
		}
	}

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
	if cfg.BuildKit.Enabled && strings.Contains(req.ShellCommand, "buildctl-daemonless.sh") {
		payloadErr := runManagedBuildKit(manifest, cwd, req.ShellCommand, callerUID, callerGID, cfg)
		cleanupErr := rt.Cleanup(ctx, deps)
		summaryErr := writeMonitorSummary(stderr, rt.MonitorSummary())
		return errors.Join(payloadErr, cleanupErr, summaryErr)
	}
	var sandboxBuildKit *managedBuildKitDaemon
	if cfg.BuildKit.Enabled {
		sandboxBuildKit, err = startSandboxBuildKitDaemon(manifest, callerUID, callerGID, cfg)
		if err != nil {
			_ = rt.Cleanup(ctx, deps)
			return fmt.Errorf("start sandbox buildkitd: %w", err)
		}
	}

	rootfsPlan, err := buildRootfsPlan(rootfs.PlanRequest{
		RootfsMode:       cfg.Sandbox.Rootfs,
		RepoPath:         repoPath,
		Workdir:          cfg.Sandbox.Workdir,
		NetworkMode:      cfg.Network.Mode,
		GatewayIP:        manifest.GatewayIP,
		SandboxHostn:     cfg.Sandbox.Hostname,
		BuildKitEnabled:  cfg.BuildKit.Enabled,
		BuildKitHelper:   cfg.BuildKit.HelperPathValue(),
		BuildKitStateDir: cfg.BuildKit.StateDirValue(),
		BuildKitRunDir:   cfg.BuildKit.RunDirValue(),
		DockerEnabled:    cfg.Docker.Enabled,
		DockerUser:       cfg.Docker.UserValue(),
		DockerUID:        cfg.Docker.UIDValue(),
		DockerGID:        cfg.Docker.GIDValue(),
		DockerHomeDir:    cfg.Docker.HomeDirValue(),
		DockerRuntimeDir: cfg.Docker.RuntimeDirValue(),
		DockerDataRoot:   cfg.Docker.DataRootValue(),
		DockerSocketPath: cfg.Docker.SocketPathValue(),
		DockerHTTPProxy:  dockerProxyValue(manifest.GatewayIP, cfg),
		DockerHTTPSProxy: dockerProxyValue(manifest.GatewayIP, cfg),
		DockerNoProxy:    dockerNoProxyValue(cfg),
		ExtraRO:          cfg.Mounts.ExtraRO,
		ExtraRW:          cfg.Mounts.ExtraRW,
	})
	if err != nil {
		_ = stopSandboxBuildKitDaemon(sandboxBuildKit)
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
		_ = stopSandboxBuildKitDaemon(sandboxBuildKit)
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("apply rootfs plan: %w", err)
	}
	extraEnv := sandboxProxyAndBuildEnv(manifest.GatewayIP, cfg)
	if sandboxBuildKit != nil {
		extraEnv = append(extraEnv, envBuildKitHost+"="+sandboxBuildKit.addr)
		if noProxy := buildKitControlNoProxy(sandboxBuildKit.addr); noProxy != "" {
			extraEnv = append(extraEnv, "NO_PROXY="+noProxy)
		}
		if buildUsesProxy(cfg) {
			proxy := proxyURL("127.0.0.1", cfg.Network.TransparentProxy.HTTPPort)
			extraEnv = append(extraEnv,
				envBuildKitHTTPProxy+"="+proxy,
				envBuildKitHTTPSProxy+"="+proxy,
				envBuildKitNoProxy+"="+defaultNoProxy,
			)
		}
		extraEnv = append(extraEnv, envBuildKitHome+"=/tmp/box-buildkit-home")
	}

	spec, err := buildSandboxSpec(gvisor.BuildSpecRequest{
		Config:               cfg,
		Workdir:              cfg.Sandbox.Workdir,
		Payload:              req.ShellCommand,
		HostEnv:              os.Environ(),
		ExtraEnv:             extraEnv,
		RootfsPlan:           rootfsPlan,
		NetworkNamespacePath: sandboxNetworkNamespacePath(cfg, manifest.Net.NetNS),
	})
	if err != nil {
		_ = stopSandboxBuildKitDaemon(sandboxBuildKit)
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build sandbox spec: %w", err)
	}
	if err := writeBundleSpec(bundleDir, spec); err != nil {
		_ = stopSandboxBuildKitDaemon(sandboxBuildKit)
		_ = rt.Cleanup(ctx, deps)
		return err
	}
	if cfg.BuildKit.Enabled {
		if err := chownTree(filepath.Join(manifest.StateDir, "bundle"), callerUID, callerGID); err != nil {
			_ = stopSandboxBuildKitDaemon(sandboxBuildKit)
			_ = rt.Cleanup(ctx, deps)
			return fmt.Errorf("chown bundle for rootless runsc: %w", err)
		}
	}

	runReq := gvisor.RunRequest{
		BundleDir:       bundleDir,
		ContainerID:     manifest.RuntimeID,
		NetNS:           manifest.Net.NetNS,
		DockerEnabled:   cfg.Docker.Enabled,
		BuildKitEnabled: cfg.BuildKit.Enabled,
	}
	if cfg.BuildKit.Enabled {
		runReq.CallerUID = callerUID
		runReq.CallerGID = callerGID
	}

	payloadErr := runSandbox(runReq)
	buildKitErr := stopSandboxBuildKitDaemon(sandboxBuildKit)
	cleanupErr := rt.Cleanup(ctx, deps)
	summaryErr := writeMonitorSummary(stderr, rt.MonitorSummary())
	return errors.Join(payloadErr, buildKitErr, cleanupErr, summaryErr)
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

	httpListener, err := deps.listen("tcp", proxyListenAddress(req.GatewayIP, req.Config.HTTPPort))
	if err != nil {
		return nil, err
	}
	tlsListener, err := deps.listen("tcp", proxyListenAddress(req.GatewayIP, req.Config.TLSPort))
	if err != nil {
		_ = httpListener.Close()
		return nil, fmt.Errorf("listen tls on port %d: %w", req.Config.TLSPort, err)
	}

	httpServer, err := deps.startHTTP(ctx, proxy.ProxyConfig{
		Listen:          consumeListener(httpListener),
		ResolveUpstream: deps.resolveUpstream,
		AllowHostname:   req.AllowHostname,
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
		AllowHostname:   req.AllowHostname,
		OnEvent:         onEvent,
	})
	if err != nil {
		_ = httpServer.Close()
		_ = tlsListener.Close()
		return nil, err
	}

	var localhostHTTP *proxy.Server
	if strings.TrimSpace(req.GatewayIP) != "" {
		localhostListener, err := net.Listen("tcp", proxyListenAddress("127.0.0.1", req.Config.HTTPPort))
		if err != nil {
			_ = httpServer.Close()
			_ = tlsServer.Close()
			return nil, fmt.Errorf("listen buildkit localhost proxy on port %d: %w", req.Config.HTTPPort, err)
		}
		localhostHTTP, err = deps.startHTTP(ctx, proxy.ProxyConfig{
			Listen:          consumeListener(localhostListener),
			ResolveUpstream: deps.resolveUpstream,
			AllowHostname:   req.AllowHostname,
			OnEvent:         onEvent,
		})
		if err != nil {
			_ = localhostListener.Close()
			_ = httpServer.Close()
			_ = tlsServer.Close()
			return nil, err
		}
	}

	return proxyRunner{
		http:          httpServer,
		tls:           tlsServer,
		localhostHTTP: localhostHTTP,
	}, nil
}

type proxyRunner struct {
	http          *proxy.Server
	tls           *proxy.Server
	localhostHTTP *proxy.Server
}

func (r proxyRunner) Stop() error {
	return errors.Join(closeProxyServer(r.localhostHTTP), closeProxyServer(r.tls), closeProxyServer(r.http))
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

func proxyListenAddress(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ":" + strconv.Itoa(port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
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

	if req.Net.RouteTable > 0 || req.Net.FWMark != 0 {
		conflict, err := policyRuleConflict(ctx, run, req.Net.FWMark, req.Net.RouteTable)
		if err != nil {
			return errors.Join(boxruntime.ErrResourceConflict, err)
		}
		if strings.TrimSpace(conflict) != "" {
			return errors.Join(boxruntime.ErrResourceConflict, errors.New(conflict))
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

func policyRuleConflict(ctx context.Context, run preflightCommandRunner, fwmark uint32, routeTable int) (string, error) {
	out, err := run(ctx, "ip", "-o", "rule", "show")
	if err != nil {
		return "", fmt.Errorf("query ip rules: %w: %s", err, strings.TrimSpace(out))
	}

	lookupNeedle := fmt.Sprintf("lookup %d", routeTable)
	fwmarkHexNeedle := fmt.Sprintf("fwmark 0x%x", fwmark)
	fwmarkDecNeedle := fmt.Sprintf("fwmark %d", fwmark)
	for _, line := range strings.Split(out, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" {
			continue
		}
		if routeTable > 0 && strings.Contains(clean, lookupNeedle) {
			return fmt.Sprintf("ip policy rule already references route table %d", routeTable), nil
		}
		if fwmark != 0 && (strings.Contains(clean, fwmarkHexNeedle) || strings.Contains(clean, fwmarkDecNeedle)) {
			return fmt.Sprintf("ip policy rule already references fwmark %d", fwmark), nil
		}
	}

	return "", nil
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

func sandboxProxyAndBuildEnv(gatewayIP string, cfg config.Config) []string {
	var env []string
	if buildUsesProxy(cfg) {
		proxy := proxyURL(gatewayIP, cfg.Network.TransparentProxy.HTTPPort)
		env = append(env,
			"HTTP_PROXY="+proxy,
			"HTTPS_PROXY="+proxy,
			"NO_PROXY="+defaultNoProxy,
		)
	}
	if !cfg.Docker.Enabled {
		if !cfg.BuildKit.Enabled {
			return env
		}
	} else if dockerUsesProxy(cfg) {
		env = append(env, envDockerConfig+"="+dockerConfigDir)
	}

	if cfg.BuildKit.Enabled {
		pathValue := pathEnvValue(cfg.Sandbox.Env)
		if !strings.HasPrefix(pathValue, buildkitPathDir+":") && !strings.Contains(pathValue, ":"+buildkitPathDir) && pathValue != buildkitPathDir {
			pathValue = buildkitPathDir + ":" + pathValue
		}
		env = append(env,
			"PATH="+pathValue,
			envBuildKitdFlags+"=--root "+cfg.BuildKit.StateDirValue()+" --rootless --oci-worker-rootless --oci-worker-no-process-sandbox",
		)
	}

	if !cfg.Docker.Enabled {
		return env
	}

	socketPath := cfg.Docker.SocketPathValue()

	return append(env,
		envDockerEnabled+"=1",
		envDockerMode+"="+cfg.Docker.ModeValue(),
		envDockerUser+"="+cfg.Docker.UserValue(),
		envDockerUID+"="+strconv.Itoa(cfg.Docker.UIDValue()),
		envDockerGID+"="+strconv.Itoa(cfg.Docker.GIDValue()),
		envDockerHome+"="+cfg.Docker.HomeDirValue(),
		envDockerRuntimeDir+"="+cfg.Docker.RuntimeDirValue(),
		envDockerDataRoot+"="+cfg.Docker.DataRootValue(),
		envDockerHost+"=unix://"+socketPath,
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

func buildUsesProxy(cfg config.Config) bool {
	if modeUsesProxy(cfg) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Network.Mode), "enforce") &&
		cfg.Network.TransparentProxy.Enabled &&
		cfg.BuildKit.Enabled
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

func rootlessCallerFromEnv(getenv func(string) string) (int, int, error) {
	uidValue := strings.TrimSpace(getenv("SUDO_UID"))
	gidValue := strings.TrimSpace(getenv("SUDO_GID"))
	if uidValue == "" || gidValue == "" {
		return 0, 0, errors.New("buildkit rootless mode requires SUDO_UID and SUDO_GID from the original invoking user")
	}
	uid, err := strconv.Atoi(uidValue)
	if err != nil || uid <= 0 {
		return 0, 0, fmt.Errorf("parse SUDO_UID: %q", uidValue)
	}
	gid, err := strconv.Atoi(gidValue)
	if err != nil || gid <= 0 {
		return 0, 0, fmt.Errorf("parse SUDO_GID: %q", gidValue)
	}
	return uid, gid, nil
}

func rootlessHomeDir(uid int) (string, error) {
	if home := strings.TrimSpace(os.Getenv("SUDO_HOME")); home != "" {
		return home, nil
	}
	entry, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("lookup home for uid %d: %w", uid, err)
	}
	home := strings.TrimSpace(entry.HomeDir)
	if home == "" {
		return "", fmt.Errorf("lookup home for uid %d returned empty home dir", uid)
	}
	return home, nil
}

func chownTree(root string, uid int, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

func ensureRootlessRuntimeDir(uid int, gid int) error {
	root := filepath.Join("/run/user", strconv.Itoa(uid))
	for _, dir := range []string{
		root,
		filepath.Join(root, "runsc"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

type managedBuildKitDaemon struct {
	cmd     *exec.Cmd
	logPath string
	addr    string
	ln      net.Listener
	wg      sync.WaitGroup
}

func startSandboxManagedBuildKitDaemon(manifest boxruntime.Manifest, uid int, gid int, cfg config.Config) (*managedBuildKitDaemon, error) {
	stateDir := filepath.Join(manifest.StateDir, "sandbox-buildkit-state")
	tmpDir := filepath.Join(manifest.StateDir, "sandbox-buildkit-tmp")
	logPath := filepath.Join(manifest.StateDir, "sandbox-buildkitd.log")
	for _, dir := range []string{stateDir, tmpDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return nil, err
		}
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	runtimeDir := filepath.Join("/run/user", strconv.Itoa(uid))
	homeDir, err := rootlessHomeDir(uid)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	runcWrapperPath, err := writeRootlessRuncWrapper(manifest.StateDir, runtimeDir, uid, gid)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	envArgs := managedBuildKitDaemonEnv(cfg)
	socketPath := filepath.Join(stateDir, "buildkitd.sock")
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = logFile.Close()
		return nil, err
	}
	listenAddr := "unix://" + socketPath
	clientAddr := "tcp://" + net.JoinHostPort(manifest.GatewayIP, "1234")
	envArgs = append(envArgs,
		"PATH="+pathEnvValue(cfg.Sandbox.Env),
		"TMPDIR="+tmpDir,
		"XDG_RUNTIME_DIR="+runtimeDir,
		"HOME="+homeDir,
		"buildkitd",
		"--root", stateDir,
		"--addr", listenAddr,
		"--rootless",
		"--oci-worker-binary", runcWrapperPath,
		"--oci-worker-rootless",
		"--oci-worker-no-process-sandbox",
	)
	commandName, commandArgs, err := launcher.HostCommand(launcher.Request{
		Binary: "env",
		Args:   envArgs,
		UID:    uid,
		GID:    gid,
	})
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	cmd := exec.Command(commandName, commandArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	_ = logFile.Close()
	daemon := &managedBuildKitDaemon{
		cmd:     cmd,
		logPath: logPath,
		addr:    clientAddr,
	}
	if err := waitForManagedBuildKitDaemon(listenAddr, daemon.logPath, uid, gid); err != nil {
		_ = stopManagedBuildKitDaemon(daemon)
		return nil, err
	}
	if err := startManagedBuildKitControlProxy(daemon, manifest.GatewayIP, 1234, listenAddr); err != nil {
		_ = stopManagedBuildKitDaemon(daemon)
		return nil, err
	}
	return daemon, nil
}

func managedBuildKitDaemonEnv(cfg config.Config) []string {
	if !buildUsesProxy(cfg) {
		return nil
	}
	proxy := proxyURL("127.0.0.1", cfg.Network.TransparentProxy.HTTPPort)
	return []string{
		"HTTP_PROXY=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"NO_PROXY=" + defaultNoProxy,
	}
}

func buildKitControlNoProxy(addr string) string {
	value := defaultNoProxy
	hostPort := strings.TrimPrefix(strings.TrimSpace(addr), "tcp://")
	if host, _, err := net.SplitHostPort(hostPort); err == nil && strings.TrimSpace(host) != "" {
		value += "," + strings.TrimSpace(host)
	}
	return value
}

func waitForManagedBuildKitDaemon(addr string, logPath string, uid int, gid int) error {
	var lastErr error
	for i := 0; i < 50; i++ {
		commandName, commandArgs, err := launcher.UserCommand(launcher.Request{
			Binary: "buildctl",
			Args:   []string{"--addr=" + addr, "debug", "workers"},
			UID:    uid,
			GID:    gid,
		})
		if err != nil {
			return err
		}
		cmd := exec.Command(commandName, commandArgs...)
		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	logData, _ := os.ReadFile(logPath)
	if strings.TrimSpace(string(logData)) == "" {
		return fmt.Errorf("wait for buildkitd at %q: %w", addr, lastErr)
	}
	return fmt.Errorf("wait for buildkitd at %q: %w: %s", addr, lastErr, strings.TrimSpace(string(logData)))
}

func stopManagedBuildKitDaemon(daemon *managedBuildKitDaemon) error {
	if daemon == nil {
		return nil
	}
	if daemon.ln != nil {
		_ = daemon.ln.Close()
	}
	daemon.wg.Wait()
	if daemon.cmd == nil {
		return nil
	}
	if daemon.cmd.ProcessState != nil {
		return nil
	}
	if err := daemon.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		_ = daemon.cmd.Process.Kill()
	}
	if err := daemon.cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
		return err
	}
	return nil
}

func startManagedBuildKitControlProxy(daemon *managedBuildKitDaemon, listenHost string, port int, targetAddr string) error {
	if daemon == nil {
		return errors.New("managed buildkit daemon is required")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(strings.TrimSpace(listenHost), strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("listen buildkit control proxy on %s:%d: %w", strings.TrimSpace(listenHost), port, err)
	}
	daemon.ln = ln
	daemon.wg.Add(1)
	go func() {
		defer daemon.wg.Done()
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			daemon.wg.Add(1)
			go func(client net.Conn) {
				defer daemon.wg.Done()
				defer client.Close()
				upstream, err := dialManagedBuildKitEndpoint(targetAddr)
				if err != nil {
					return
				}
				defer upstream.Close()
				copyDone := make(chan struct{}, 2)
				go proxyHalf(upstream, client, copyDone)
				go proxyHalf(client, upstream, copyDone)
				<-copyDone
				_ = client.Close()
				_ = upstream.Close()
				<-copyDone
			}(clientConn)
		}
	}()
	return nil
}

func dialManagedBuildKitEndpoint(addr string) (net.Conn, error) {
	trimmed := strings.TrimSpace(addr)
	switch {
	case strings.HasPrefix(trimmed, "unix://"):
		return net.Dial("unix", strings.TrimPrefix(trimmed, "unix://"))
	case strings.HasPrefix(trimmed, "tcp://"):
		return net.Dial("tcp", strings.TrimPrefix(trimmed, "tcp://"))
	default:
		return net.Dial("tcp", trimmed)
	}
}

func proxyHalf(dst net.Conn, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}

func runManagedBuildKit(manifest boxruntime.Manifest, repoPath string, shellCommand string, uid int, gid int, cfg config.Config) error {
	helperDir := filepath.Join(manifest.StateDir, "buildkit-bin")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		return err
	}
	helperPath := filepath.Join(helperDir, "buildctl-daemonless.sh")
	if err := os.WriteFile(helperPath, []byte(hostBuildctlDaemonlessScript()), 0o755); err != nil {
		return err
	}
	stateDir := filepath.Join(manifest.StateDir, "buildkit-state")
	runDir := filepath.Join(manifest.StateDir, "buildkit-run")
	tmpDir := filepath.Join(manifest.StateDir, "tmp")
	for _, dir := range []string{stateDir, runDir, tmpDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for _, path := range []string{helperDir, helperPath, stateDir, runDir, tmpDir} {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/run/buildkit", 0o700); err != nil {
		return err
	}
	if err := os.Chown("/run/buildkit", uid, gid); err != nil {
		return err
	}
	if err := os.Chmod("/run/buildkit", 0o700); err != nil {
		return err
	}

	pathValue := pathEnvValue(cfg.Sandbox.Env)
	if !strings.HasPrefix(pathValue, helperDir+":") && !strings.Contains(pathValue, ":"+helperDir) && pathValue != helperDir {
		pathValue = helperDir + ":" + pathValue
	}
	runtimeDir := filepath.Join("/run/user", strconv.Itoa(uid))
	homeDir, err := rootlessHomeDir(uid)
	if err != nil {
		return err
	}
	runcWrapperPath, err := writeRootlessRuncWrapper(manifest.StateDir, runtimeDir, uid, gid)
	if err != nil {
		return err
	}
	envArgs := append([]string(nil), managedBuildKitDaemonEnv(cfg)...)
	envArgs = append(envArgs,
		"PATH="+pathValue,
		"TMPDIR="+tmpDir,
		"XDG_RUNTIME_DIR="+runtimeDir,
		"HOME="+homeDir,
		"BUILDKIT_RUN_DIR="+runDir,
		"BUILDKITD_FLAGS=--root "+stateDir+" --rootless --oci-worker-binary "+runcWrapperPath+" --oci-worker-rootless --oci-worker-no-process-sandbox",
		"bash",
		"-lc",
		buildkitShellCommand(manifest.GatewayIP, repoPath, shellCommand),
	)
	commandName, commandArgs, err := launcher.HostCommand(launcher.Request{
		Binary: "env",
		Args:   envArgs,
		UID:    uid,
		GID:    gid,
	})
	if err != nil {
		return err
	}
	cmd := exec.Command(commandName, commandArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildkitShellCommand(gatewayIP string, repoPath string, shellCommand string) string {
	_ = gatewayIP
	resolved := strings.ReplaceAll(shellCommand, "/box/bin/buildctl-daemonless.sh", "buildctl-daemonless.sh")
	return "cd " + shellQuote(repoPath) + " && " + resolved
}

func writeRootlessRuncWrapper(stateDir string, runtimeDir string, uid int, gid int) (string, error) {
	runcStateDir := filepath.Join(runtimeDir, "runc")
	if err := os.MkdirAll(runcStateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chown(runcStateDir, uid, gid); err != nil {
		return "", err
	}
	wrapperPath := filepath.Join(stateDir, "buildkit-runc")
	content := "#!/bin/sh\nset -eu\nexec runc --root " + shellQuote(runcStateDir) + " --rootless=true \"$@\"\n"
	if err := os.WriteFile(wrapperPath, []byte(content), 0o755); err != nil {
		return "", err
	}
	if err := os.Chown(wrapperPath, uid, gid); err != nil {
		return "", err
	}
	return wrapperPath, nil
}

func hostBuildctlDaemonlessScript() string {
	return strings.TrimSpace(`#!/bin/sh
set -eu

: ${BUILDCTL=buildctl}
: ${BUILDCTL_CONNECT_RETRIES_MAX=10}
: ${BUILDKITD=buildkitd}
: ${BUILDKIT_RUN_DIR=}
: ${BUILDKITD_FLAGS=}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/buildctl-daemonless.XXXXXX")
trap 'kill $(cat "$tmp/pid") 2>/dev/null || true; wait $(cat "$tmp/pid") 2>/dev/null || true; rm -rf "$tmp"' EXIT

start_buildkitd() {
    mkdir -p "$BUILDKIT_RUN_DIR"
    addr=unix://$BUILDKIT_RUN_DIR/buildkitd.sock
    $BUILDKITD $BUILDKITD_FLAGS --addr=$addr >"$tmp/log" 2>&1 &
    pid=$!
    echo "$pid" >"$tmp/pid"
    echo "$addr" >"$tmp/addr"
}

wait_for_buildkitd() {
    addr=$(cat "$tmp/addr")
    try=0
    max=$BUILDCTL_CONNECT_RETRIES_MAX
    until $BUILDCTL --addr=$addr debug workers >/dev/null 2>&1; do
        if [ "$try" -gt "$max" ]; then
            echo >&2 "could not connect to $addr after $max trials"
            echo >&2 "========== log =========="
            cat >&2 "$tmp/log"
            exit 1
        fi
        sleep "$(awk "BEGIN{print (100 + $try * 20) * 0.001}")"
        try=$(expr "$try" + 1)
    done
}

start_buildkitd
wait_for_buildkitd
exec $BUILDCTL --addr="$(cat "$tmp/addr")" "$@"
`) + "\n"
}

func sandboxNetworkNamespacePath(cfg config.Config, netNS string) string {
	_ = cfg
	if strings.TrimSpace(netNS) == "" {
		return ""
	}
	return filepath.Join("/run/netns", netNS)
}

func pathEnvValue(configEnv []string) string {
	for _, entry := range configEnv {
		if strings.HasPrefix(entry, "PATH=") {
			return strings.TrimPrefix(entry, "PATH=")
		}
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

type stopFunc func() error

func (f stopFunc) Stop() error {
	return f()
}
