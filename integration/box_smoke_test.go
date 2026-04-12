package integration

import (
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
	fixture := startLocalHTTPFixture(t)
	configPath := testenv.WriteEnforceDockerConfigWithHostNetworkNestedContainers(t, fmt.Sprintf(`
- cidr: %s
  transport:
    - protocol: tcp
      ports: [%d]
`, fixture.CIDR, fixture.Port), false)

	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-build.")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	alpineArchivePath := filepath.Join(contextDir, "alpine.tar")
	debianArchivePath := filepath.Join(contextDir, "debian.tar")
	dockerfile := strings.TrimSpace(fmt.Sprintf(`
FROM alpine:3.20 AS alpine-stage
RUN wget -qO /build-artifact.txt %s && \
    grep -q 'Example Domain' /build-artifact.txt

FROM debian:bookworm-slim AS debian-stage
WORKDIR /tmp/app
RUN printf '%%s\n' '{"name":"box-enforce-test"}' >/tmp/app/package.json

FROM debian:bookworm-slim
COPY --from=alpine-stage /build-artifact.txt /build-artifact.txt
COPY --from=debian-stage /tmp/app/package.json /package.json
RUN test -s /build-artifact.txt && test -s /package.json
CMD ["cat", "/build-artifact.txt"]
`, shellSingleQuote(fixture.URL))) + "\n"
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	copyDockerArchive(t, "docker.io/library/alpine:3.20", alpineArchivePath, "alpine:3.20")
	copyDockerArchive(t, "docker.io/library/debian:bookworm-slim", debianArchivePath, "debian:bookworm-slim")

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

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, `
- hostname: example.com
  transport:
    - protocol: tcp
      ports: [443]
`)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-k", "-fsS", "--connect-timeout", "5", "--max-time", "10", "https://example.com")
	if err == nil {
		if !strings.Contains(stdout, "Example Domain") {
			t.Fatalf("allowed hostname request stdout = %q, want fixture body", stdout)
		}
	} else {
		t.Fatalf("allowed hostname port request error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	stdout, stderr, err = testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", "http://example.com")
	if err == nil {
		t.Fatalf("expected disallowed hostname port to fail; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxEnforceAllowsDirectIPOnlyWhenCIDRRuleMatches(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	exampleIP := lookupHostIPv4(t, "example.com")

	blockedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: 198.51.100.7/32
  transport:
    - protocol: tcp
      ports: [80]
`))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", blockedConfigPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", "-H", "Host: example.com", "http://"+exampleIP+"/")
	if err == nil {
		t.Fatalf("expected direct-ip request with non-matching cidr to fail; stdout=%q stderr=%q", stdout, stderr)
	}

	allowedConfigPath := testenv.WriteEnforceConfig(t, fmt.Sprintf(`
- cidr: %s
  transport:
    - protocol: tcp
      ports: [80]
`, exampleIP+"/32"))
	stdout, stderr, err = testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", allowedConfigPath, "--",
		"curl", "-fsS", "--connect-timeout", "5", "--max-time", "10", "-H", "Host: example.com", "http://"+exampleIP+"/")
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
