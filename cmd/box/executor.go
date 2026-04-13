package main

import (
	"bytes"
	"context"
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

	"gvisor-net/internal/config"
	ienvoy "gvisor-net/internal/envoy"
	"gvisor-net/internal/gvisor"
	"gvisor-net/internal/policyd"
	"gvisor-net/internal/rootfs"
	boxruntime "gvisor-net/internal/runtime"
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
		CommandExec:        hostCommandExec{},
		StartPolicyService: startPolicyService,
		StartEnvoy:         startEnvoyRunner,
		MonitorPreflight:   monitorPreflight,
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

	runtimeCACert, err := readRuntimeCACert(manifest)
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("read runtime ca cert: %w", err)
	}
	trustedCACert := boxruntime.BuildSandboxTrustBundlePEM(runtimeCACert)

	rootfsPlan, err := buildRootfsPlan(rootfs.PlanRequest{
		RootfsMode:        cfg.Sandbox.Rootfs,
		RepoPath:          repoPath,
		Workdir:           cfg.Sandbox.Workdir,
		NetworkMode:       cfg.Network.Mode,
		GatewayIP:         manifest.GatewayIP,
		SandboxHostn:      cfg.Sandbox.Hostname,
		ExtraRO:           cfg.Mounts.ExtraRO,
		ExtraRW:           cfg.Mounts.ExtraRW,
		RuntimeCACertPEM:  runtimeCACert,
		TrustedCACertPEM:  trustedCACert,
		TrustedCACertPath: manifest.CA.SandboxCertPath,
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
	extraEnv := sandboxProxyEnv(manifest)

	spec, err := buildSandboxSpec(gvisor.BuildSpecRequest{
		Config:               cfg,
		Workdir:              cfg.Sandbox.Workdir,
		Payload:              req.ShellCommand,
		HostEnv:              os.Environ(),
		ExtraEnv:             extraEnv,
		RuntimeManifest:      manifest,
		RootfsPlan:           rootfsPlan,
		NetworkNamespacePath: sandboxNetworkNamespacePath(cfg, manifest.Net.NetNS),
	})
	if err != nil {
		_ = rt.Cleanup(ctx, deps)
		return fmt.Errorf("build sandbox spec: %w", err)
	}
	if err := writeBundleSpec(bundleDir, spec); err != nil {
		_ = rt.Cleanup(ctx, deps)
		return err
	}
	runReq := gvisor.RunRequest{
		BundleDir:   bundleDir,
		ContainerID: manifest.RuntimeID,
		NetNS:       manifest.Net.NetNS,
		Platform:    cfg.GVisor.Platform,
	}

	payloadErr := runSandbox(runReq)
	cleanupErr := rt.Cleanup(ctx, deps)
	summaryErr := writeMonitorSummary(stderr, rt.MonitorSummary())
	return errors.Join(payloadErr, cleanupErr, summaryErr)
}

type hostCommandExec struct{}

func (hostCommandExec) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, trimmed)
}

func writeMonitorSummary(stderr io.Writer, summary string) error {
	if stderr == nil || strings.TrimSpace(summary) == "" {
		return nil
	}
	_, err := io.WriteString(stderr, summary)
	return err
}

func startPolicyService(ctx context.Context, req boxruntime.PolicyServiceStartRequest) (boxruntime.Runner, error) {
	mode := policyd.ModeEnforce
	if strings.EqualFold(strings.TrimSpace(req.Mode), "monitor") {
		mode = policyd.ModeObserve
	}
	return policyd.Start(ctx, req.ListenAddr, req.DNSListenAddr, policyd.NewService(policyd.ServiceConfig{
		Mode:        mode,
		Rules:       append([]config.NetworkPolicyRule(nil), req.Rules...),
		DNSUpstream: append([]string(nil), req.DNSUpstream...),
		OnEvent:     req.OnEvent,
	}))
}

func startEnvoyRunner(ctx context.Context, req boxruntime.EnvoyStartRequest) (boxruntime.Runner, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	binaryPath, err := ienvoy.ResolveBinary(ienvoy.BinaryLocator{
		ExecutablePath: executablePath,
	})
	if err != nil {
		return nil, err
	}
	bootstrapContent, err := ienvoy.RenderBootstrap(ienvoy.BootstrapConfig{
		NodeID:                  req.RuntimeID,
		ExplicitPort:            req.ExplicitPort,
		TransparentPort:         req.TransparentPort,
		DNSPort:                 req.DNSPort,
		DNSUpstream:             append([]string(nil), req.DNSUpstream...),
		AuthzAddress:            req.PolicyListenAddr,
		UpstreamTrustBundlePath: req.UpstreamTrustBundlePath,
		TransparentTLSCertificates: mapTransparentTLSCertificates(req.TransparentTLSCertificates),
	})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(req.BootstrapPath, []byte(bootstrapContent), 0o644); err != nil {
		return nil, err
	}
	return ienvoy.Start(ctx, ienvoy.StartRequest{
		BinaryPath:    binaryPath,
		BootstrapPath: req.BootstrapPath,
		LogPath:       req.LogPath,
	})
}

func mapTransparentTLSCertificates(in []boxruntime.TransparentTLSCertificate) []ienvoy.TLSCertificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]ienvoy.TLSCertificate, 0, len(in))
	for _, cert := range in {
		out = append(out, ienvoy.TLSCertificate{
			ServerNames: append([]string(nil), cert.ServerNames...),
			CertPath:    cert.CertPath,
			KeyPath:     cert.KeyPath,
		})
	}
	return out
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

func sandboxProxyEnv(manifest boxruntime.Manifest) []string {
	var env []string
	if modeUsesProxy(manifest) {
		proxy := proxyURL(manifest.GatewayIP, manifest.Envoy.ExplicitPort)
		env = append(env,
			"HTTP_PROXY="+proxy,
			"HTTPS_PROXY="+proxy,
			"http_proxy="+proxy,
			"https_proxy="+proxy,
			"NO_PROXY=127.0.0.1,localhost",
			"no_proxy=127.0.0.1,localhost",
		)
	}
	if strings.TrimSpace(manifest.CA.CertPath) != "" || strings.TrimSpace(manifest.CA.SandboxCertPath) != "" {
		certPath := manifest.CA.SandboxCertPath
		if strings.TrimSpace(certPath) == "" {
			certPath = rootfs.RuntimeCACertPath
		}
		env = append(env,
			"SSL_CERT_FILE="+certPath,
			"CURL_CA_BUNDLE="+certPath,
			"REQUESTS_CA_BUNDLE="+certPath,
			"NODE_EXTRA_CA_CERTS="+certPath,
		)
	}
	return env
}

func proxyURL(host string, port int) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func modeUsesProxy(manifest boxruntime.Manifest) bool {
	return strings.TrimSpace(manifest.GatewayIP) != "" &&
		manifest.Envoy.ExplicitPort > 0
}

func readRuntimeCACert(manifest boxruntime.Manifest) (string, error) {
	path := strings.TrimSpace(manifest.CA.CertPath)
	if path == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func sandboxNetworkNamespacePath(cfg config.Config, netNS string) string {
	_ = cfg
	if strings.TrimSpace(netNS) == "" {
		return ""
	}
	return filepath.Join("/run/netns", netNS)
}

type stopFunc func() error

func (f stopFunc) Stop() error {
	return f()
}
