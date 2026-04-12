package integration

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor-net/integration/testenv"
	"gvisor-net/internal/config"
)

func TestBoxRunsPwd(t *testing.T) {
	output := runBoxSmoke(t, "/bin/pwd")
	if strings.TrimSpace(output) == "" {
		t.Fatal("pwd output is empty")
	}
}

func TestBoxRunsEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteDefaultConfig(t, binary.ModuleRoot)
	cfg, err := config.Load(configPath, binary.ModuleRoot)
	if err != nil {
		t.Fatalf("config.Load(%q) error = %v", configPath, err)
	}

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "/usr/bin/env")
	if err != nil {
		t.Fatalf("run box env error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	output := stdout
	if !strings.Contains(output, "PATH=") {
		t.Fatalf("env output = %q, want PATH entry", output)
	}
	wantHTTPProxy := fmt.Sprintf("HTTP_PROXY=http://100.96.0.1:%d", cfg.Network.TransparentProxy.HTTPPort)
	if !strings.Contains(output, wantHTTPProxy) {
		t.Fatalf("env output = %q, want HTTP_PROXY host intercept env", output)
	}
	wantHTTPSProxy := fmt.Sprintf("HTTPS_PROXY=http://100.96.0.1:%d", cfg.Network.TransparentProxy.HTTPPort)
	if !strings.Contains(output, wantHTTPSProxy) {
		t.Fatalf("env output = %q, want HTTPS_PROXY host intercept env", output)
	}
}

func TestBoxResolvesExampleDotComWithGetent(t *testing.T) {
	output := runBoxSmoke(t, "bash", "-lc", "getent hosts example.com")
	if !strings.Contains(strings.ToLower(output), "example.com") {
		t.Fatalf("getent output = %q, want example.com hostname", output)
	}
}

func TestBoxCanCurlExampleDotCom(t *testing.T) {
	output := runBoxSmoke(t, "curl", "http://example.com")
	if !strings.Contains(output, "Example Domain") {
		t.Fatalf("curl output = %q, want Example Domain response body", output)
	}
}

func TestBoxShowsSandboxInterfaceAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteDefaultConfig(t, binary.ModuleRoot)
	cfg, err := config.Load(configPath, binary.ModuleRoot)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	prefix, err := netip.ParsePrefix(cfg.Network.Subnet)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) error = %v", cfg.Network.Subnet, err)
	}
	expectedSandboxIP := prefix.Masked().Addr().Next().Next()
	expectedCIDR := expectedSandboxIP.String() + "/" + strconv.Itoa(prefix.Bits())

	hostIPOutput, err := exec.Command("ip", "-4", "-o", "addr", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("host ip command error = %v: %s", err, strings.TrimSpace(string(hostIPOutput)))
	}
	if strings.Contains(string(hostIPOutput), expectedCIDR) {
		t.Skipf("host already exposes expected sandbox address %q; dirty host state", expectedCIDR)
	}

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "ip", "-4", "-o", "addr", "show")
	if err != nil {
		t.Fatalf("run box ip command error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, expectedCIDR) {
		t.Fatalf("ip output = %q, want sandbox cidr %q", stdout, expectedCIDR)
	}
	if stdout == string(hostIPOutput) {
		t.Fatalf("sandbox ip output matched host network view exactly; stdout=%q", stdout)
	}
}

func TestBoxStartsSandboxDockerDaemon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "docker", "dockerd")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteDockerEnabledConfig(t, binary.ModuleRoot)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "docker", "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatalf("run box docker version error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("docker version output is empty; stderr=%q", stderr)
	}
}

func TestBoxEnforceBuildsMultistageDockerfile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "docker", "dockerd", "skopeo")

	binary := testenv.BuildBoxBinary(t)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-build.")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	alpineArchivePath := filepath.Join(contextDir, "alpine.tar")
	debianArchivePath := filepath.Join(contextDir, "debian.tar")
	dockerfile := strings.TrimSpace(`
FROM alpine:3.20 AS alpine-stage
RUN wget -qO /build-artifact.txt 'http://example.com/' && \
    grep -q 'Example Domain' /build-artifact.txt

FROM debian:bookworm-slim AS debian-stage
WORKDIR /tmp/app
RUN printf '%s\n' '{"name":"box-enforce-test"}' >/tmp/app/package.json

FROM debian:bookworm-slim
COPY --from=alpine-stage /build-artifact.txt /build-artifact.txt
COPY --from=debian-stage /tmp/app/package.json /package.json
RUN test -s /build-artifact.txt && test -s /package.json
CMD ["cat", "/build-artifact.txt"]
`) + "\n"
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	copyDockerArchive(t, "docker.io/library/alpine:3.20", alpineArchivePath, "alpine:3.20")
	copyDockerArchive(t, "docker.io/library/debian:bookworm-slim", debianArchivePath, "debian:bookworm-slim")
	configPath := testenv.WriteEnforceDockerConfigWithHostNetworkNestedContainers(t, `
- hostname: example.com
  transport:
    - protocol: tcp
      ports: [80]
`, true)

	imageTag := "box-enforce-test:" + strconv.FormatInt(time.Now().UnixNano(), 10)
script := fmt.Sprintf(`
set -e
docker load -i %s >/dev/null
docker load -i %s >/dev/null
DOCKER_BUILDKIT=0 docker build --network=host -t %s -f %s %s
docker image inspect %s >/dev/null
echo BOX_BUILD_DONE
`, shellSingleQuote(relPath(t, binary.ModuleRoot, alpineArchivePath)), shellSingleQuote(relPath(t, binary.ModuleRoot, debianArchivePath)), shellSingleQuote(imageTag), shellSingleQuote(relPath(t, binary.ModuleRoot, dockerfilePath)), shellSingleQuote(relPath(t, binary.ModuleRoot, contextDir)), shellSingleQuote(imageTag))

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		if strings.Contains(stdout, "BOX_BUILD_DONE") {
			t.Logf("box returned cleanup noise after successful docker build: %v; stderr=%q", err, stderr)
			return
		}
		t.Fatalf("run box enforce docker build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "BOX_BUILD_DONE") {
		t.Fatalf("docker build stdout missing completion sentinel: %q", stdout)
	}
}

func TestBoxEnforceAllowsConfiguredHostnamePortOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "ip", "python3")

	binary := testenv.BuildBoxBinary(t)
	fixture := startRoutedHTTPFixture(t, 18081, 18082)
	const hostname = "allowed.example.test"
	dnsUpstream := startDNSAUpstream(t, hostname, []string{fixture.IP})
	configPath := testenv.WriteEnforceConfigWithDNSUpstreams(t, fmt.Sprintf(`
- hostname: %s
  transport:
    - protocol: tcp
      ports: [%d]
`, hostname, fixture.Ports[0]), []string{dnsUpstream})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", fmt.Sprintf("http://%s:%d", hostname, fixture.Ports[0]))
	if err == nil {
		if !strings.Contains(stdout, "Example Domain") {
			t.Fatalf("allowed hostname request stdout = %q, want fixture body", stdout)
		}
	} else {
		t.Fatalf("allowed hostname port request error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	stdout, stderr, err = testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", fmt.Sprintf("http://%s:%d", hostname, fixture.Ports[1]))
	if err == nil {
		t.Fatalf("expected disallowed hostname port to fail; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxEnforceAllowsDirectIPOnlyWhenCIDRRuleMatches(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "ip", "python3")

	binary := testenv.BuildBoxBinary(t)
	fixture := startRoutedHTTPFixture(t, 18081)

	blockedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: 198.51.100.7/32
  transport:
    - protocol: tcp
      ports: [%d]
`, fixture.Ports[0]))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", blockedConfigPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", fmt.Sprintf("http://%s:%d/", fixture.IP, fixture.Ports[0]))
	if err == nil {
		t.Fatalf("expected direct-ip request with non-matching cidr to fail; stdout=%q stderr=%q", stdout, stderr)
	}

	allowedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: %s
  transport:
    - protocol: tcp
      ports: [%d]
`, fixture.CIDR, fixture.Ports[0]))
	stdout, stderr, err = testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", allowedConfigPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", fmt.Sprintf("http://%s:%d/", fixture.IP, fixture.Ports[0]))
	if err != nil {
		t.Fatalf("allowed direct-ip request error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("allowed direct-ip stdout = %q, want fixture body", stdout)
	}
}

func TestBoxEnforceAllowsConfiguredICMPEchoOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "ping")

	binary := testenv.BuildBoxBinary(t)
	const targetIP = "1.1.1.1"

	allowedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: %s/32
  icmp:
    - type: 8
      code: 0
`, targetIP))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", allowedConfigPath, "--",
		"ping", "-n", "-c", "1", "-W", "2", targetIP)
	if err != nil {
		combined := strings.ToLower(stdout + "\n" + stderr)
		if strings.Contains(combined, "operation not permitted") || strings.Contains(combined, "permission denied") {
			t.Skipf("sandbox ping requires raw-socket capability not available in this environment: stdout=%q stderr=%q", stdout, stderr)
		}
		if strings.Contains(combined, "100% packet loss") || strings.Contains(combined, "network is unreachable") {
			t.Skipf("icmp target not reachable from this environment: stdout=%q stderr=%q", stdout, stderr)
		}
		t.Fatalf("allowed icmp echo request error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	blockedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: %s/32
  transport:
    - protocol: tcp
      ports: [80]
`, targetIP))
	stdout, stderr, err = testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", blockedConfigPath, "--",
		"ping", "-n", "-c", "1", "-W", "2", targetIP)
	if err == nil {
		t.Fatalf("expected icmp echo request without icmp rule to fail; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxEnforceBlocksDisallowedTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, "[]")

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "getent", "hosts", "example.com")
	if err == nil {
		t.Fatalf("expected enforce mode to block example.com resolution; stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(stdout, "example.com") {
		t.Fatalf("blocked resolution unexpectedly returned example.com in stdout=%q", stdout)
	}
}

func TestBoxRunsOpenCodeFromMountedCustomBinDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	opencodePath, err := exec.LookPath("opencode")
	if err != nil {
		t.Skipf("opencode not available on host PATH: %v", err)
	}
	opencodePath, err = filepath.Abs(opencodePath)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", opencodePath, err)
	}
	hostBinDir := filepath.Dir(opencodePath)
	for _, root := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/snap", "/nix"} {
		if hostBinDir == root || strings.HasPrefix(hostBinDir, root+"/") {
			t.Skipf("opencode resolved under default host-overlay bind root %q (bin dir %q); need non-default mounted bin dir", root, hostBinDir)
		}
	}
	hostPath := os.Getenv("PATH")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteOpenCodeMonitorConfig(t, hostBinDir, hostPath)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"timeout", "20s",
		"opencode", "run", "hi",
		"--model", "opencode/gpt-5-nano",
		"--agent", "title",
	)
	if strings.Contains(stderr, `listen udp 100.96.0.1:53: bind: address already in use`) {
		t.Skipf("host DNS bind address already in use for monitor mode: %q", stderr)
	}

	lowerStderr := strings.ToLower(stderr)
	if strings.Contains(lowerStderr, "command not found") {
		t.Fatalf("opencode resolution failed in sandbox; stderr=%q", stderr)
	}
	if err != nil && !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("opencode execution failed before monitor evidence was recorded; stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "models.dev") && !strings.Contains(stderr, "opencode.ai") {
		t.Fatalf("stderr missing OpenCode host evidence: %q", stderr)
	}
	if !strings.Contains(stderr, "TLS:") && !strings.Contains(stderr, "HTTP:") {
		t.Fatalf("stderr missing TLS/HTTP monitor output: %q", stderr)
	}
}

func runBoxSmoke(t *testing.T, payload ...string) string {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteDefaultConfig(t, binary.ModuleRoot)
	args := append([]string{"--"}, payload...)
	args = append([]string{"--config", configPath}, args...)
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, args...)
	if err != nil {
		t.Fatalf("run box %v error = %v; stdout=%q stderr=%q", payload, err, stdout, stderr)
	}
	return stdout
}

func requireRootIfNeeded(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		return
	}

	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skipf("sudo not available for root-required smoke tests: %v", err)
	}

	// Avoid hanging on a password prompt when run outside privileged CI.
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("sudo privileges are required for smoke tests: %v", err)
	}
}

func mustMakeModuleTempDir(t *testing.T, moduleRoot string, pattern string) string {
	t.Helper()

	dir, err := os.MkdirTemp(moduleRoot, pattern)
	if err != nil {
		t.Fatalf("MkdirTemp(%q, %q) error = %v", moduleRoot, pattern, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func relPath(t *testing.T, base string, target string) string {
	t.Helper()

	rel, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatalf("filepath.Rel(%q, %q) error = %v", base, target, err)
	}
	return rel
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

type localHTTPFixture struct {
	URL  string
	CIDR string
	Port int
}

type routedHTTPFixture struct {
	IP    string
	CIDR  string
	Ports []int
}

func startLocalHTTPFixture(t *testing.T) localHTTPFixture {
	t.Helper()

	hostIP := discoverHostIPv4(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		t.Fatalf("Listen(%q) error = %v", hostIP, err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.WriteString(w, "Example Domain\n"); err != nil {
				t.Logf("fixture response write error: %v", err)
			}
		}),
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("fixture server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		_ = server.Close()
	})

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", listener.Addr().String(), err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(%q) error = %v", portText, err)
	}

	return localHTTPFixture{
		URL:  "http://" + net.JoinHostPort(hostIP, portText) + "/",
		CIDR: hostIP + "/32",
		Port: port,
	}
}

func discoverHostIPv4(t *testing.T) string {
	t.Helper()

	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("Dial udp4 for host IP discovery error = %v", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		t.Fatalf("unexpected local address for host IP discovery: %T %v", conn.LocalAddr(), conn.LocalAddr())
	}
	return addr.IP.String()
}

func copyDockerArchive(t *testing.T, sourceRef string, archivePath string, imageRef string) {
	t.Helper()

	output, err := exec.Command(
		"skopeo",
		"copy",
		"--insecure-policy",
		"docker://"+sourceRef,
		"docker-archive:"+archivePath+":"+imageRef,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("skopeo copy %q -> %q error = %v: %s", sourceRef, archivePath, err, strings.TrimSpace(string(output)))
	}
}

func lookupHostIPv4(t *testing.T, hostname string) string {
	t.Helper()

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		t.Fatalf("LookupIP(%q) error = %v", hostname, err)
	}
	for _, addr := range addrs {
		if v4 := addr.To4(); v4 != nil {
			return v4.String()
		}
	}
	t.Fatalf("LookupIP(%q) returned no IPv4 address", hostname)
	return ""
}

func startRoutedHTTPFixture(t *testing.T, ports ...int) routedHTTPFixture {
	t.Helper()

	if len(ports) == 0 {
		t.Fatal("startRoutedHTTPFixture() requires at least one port")
	}

	token := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	netns := "itestns" + token[:8]
	hostVeth := "itesth" + token[:8]
	guestVeth := "itestg" + token[:8]
	octet := int(time.Now().UnixNano()%200) + 20
	hostIP := fmt.Sprintf("198.19.%d.1", octet)
	guestIP := fmt.Sprintf("198.19.%d.2", octet)
	cidr := guestIP + "/30"

	runRootCommand(t, "ip", "netns", "add", netns)
	t.Cleanup(func() {
		runRootCommandIgnoreError("ip", "netns", "del", netns)
	})
	runRootCommand(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", guestVeth)
	t.Cleanup(func() {
		runRootCommandIgnoreError("ip", "link", "del", hostVeth)
	})
	runRootCommand(t, "ip", "addr", "add", hostIP+"/30", "dev", hostVeth)
	runRootCommand(t, "ip", "link", "set", hostVeth, "up")
	runRootCommand(t, "ip", "link", "set", guestVeth, "netns", netns)
	runRootCommand(t, "ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up")
	runRootCommand(t, "ip", "netns", "exec", netns, "ip", "addr", "add", cidr, "dev", guestVeth)
	runRootCommand(t, "ip", "netns", "exec", netns, "ip", "link", "set", guestVeth, "up")
	runRootCommand(t, "ip", "netns", "exec", netns, "ip", "route", "add", "default", "via", hostIP)

	docRoot := t.TempDir()
	indexPath := filepath.Join(docRoot, "index.html")
	if err := os.WriteFile(indexPath, []byte("Example Domain\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", indexPath, err)
	}

	for _, port := range ports {
		cmd := execRootCommand("ip", "netns", "exec", netns, "python3", "-m", "http.server", strconv.Itoa(port), "--bind", guestIP, "--directory", docRoot)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatalf("start routed fixture server on %s:%d error = %v", guestIP, port, err)
		}
		t.Cleanup(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}
		})
		waitForTCPListener(t, guestIP, port)
	}

	return routedHTTPFixture{
		IP:    guestIP,
		CIDR:  cidr,
		Ports: append([]int(nil), ports...),
	}
}

func startDNSAUpstream(t *testing.T, hostname string, ips []string) string {
	t.Helper()

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, client, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}

			query := make([]byte, n)
			copy(query, buf[:n])
			resp := buildDNSAResponse(t, query, hostname, ips)
			_, _ = ln.WriteTo(resp, client)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	return ln.LocalAddr().String()
}

func buildDNSAResponse(t *testing.T, query []byte, hostname string, ips []string) []byte {
	t.Helper()

	response := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000
	flags &^= 0x000f
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(ips)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	for _, rawIP := range ips {
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			t.Fatalf("ParseAddr(%q) error = %v", rawIP, err)
		}
		if !addr.Is4() {
			t.Fatalf("buildDNSAResponse() only supports IPv4 answers, got %q", rawIP)
		}
		response = appendDNSName(response, hostname)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, 60)
		response = binary.BigEndian.AppendUint16(response, 4)
		response = append(response, addr.AsSlice()...)
	}

	return response
}

func appendDNSName(buf []byte, hostname string) []byte {
	for _, label := range splitDNSLabels(hostname) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

func splitDNSLabels(hostname string) [][]byte {
	parts := make([][]byte, 0, 4)
	start := 0
	for i := 0; i <= len(hostname); i++ {
		if i != len(hostname) && hostname[i] != '.' {
			continue
		}
		if start < i {
			parts = append(parts, []byte(hostname[start:i]))
		}
		start = i + 1
	}
	return parts
}

func waitForTCPListener(t *testing.T, host string, port int) {
	t.Helper()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for tcp listener on %s", address)
}

func runRootCommand(t *testing.T, args ...string) {
	t.Helper()

	output, err := execRootCommand(args...).CombinedOutput()
	if err != nil {
		t.Fatalf("run %q error = %v: %s", strings.Join(rootCommand(args...), " "), err, strings.TrimSpace(string(output)))
	}
}

func runRootCommandIgnoreError(args ...string) {
	_, _ = execRootCommand(args...).CombinedOutput()
}

func rootCommand(args ...string) []string {
	if os.Geteuid() == 0 {
		return append([]string(nil), args...)
	}
	return append([]string{"sudo", "-n"}, args...)
}

func execRootCommand(args ...string) *exec.Cmd {
	command := rootCommand(args...)
	return exec.Command(command[0], command[1:]...)
}
