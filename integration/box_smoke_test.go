package integration

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gvisor-net/integration/testenv"
	"gvisor-net/internal/config"
)

const buildKitRemoteFetchURL = "http://1.1.1.1/cdn-cgi/trace"

func TestBoxRunsPwd(t *testing.T) {
	output := runBoxSmoke(t, "/bin/pwd")
	if strings.TrimSpace(output) == "" {
		t.Fatal("pwd output is empty")
	}
}

func TestBoxRunsEnv(t *testing.T) {
	output := runBoxSmoke(t, "/usr/bin/env")
	if !strings.Contains(output, "PATH=") {
		t.Fatalf("env output = %q, want PATH entry", output)
	}
	if !strings.Contains(output, "HTTP_PROXY=http://100.96.0.1:18080") {
		t.Fatalf("env output = %q, want HTTP_PROXY host intercept env", output)
	}
	if !strings.Contains(output, "HTTPS_PROXY=http://100.96.0.1:18080") {
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
	cfg, err := config.Load("box.yaml", binary.ModuleRoot)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	prefix, err := netip.ParsePrefix(cfg.Network.Subnet)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) error = %v", cfg.Network.Subnet, err)
	}
	hostIPOutput, err := exec.Command("ip", "-4", "-o", "addr", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("host ip command error = %v: %s", err, strings.TrimSpace(string(hostIPOutput)))
	}

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--", "ip", "-4", "-o", "addr", "show")
	if err != nil {
		t.Fatalf("run box ip command error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	sandboxCIDR := firstNonLoopbackIPv4Prefix(t, stdout)
	if sandboxCIDR.Bits() != 30 {
		t.Fatalf("sandbox interface prefix = %q, want /30 allocation from subnet pool", sandboxCIDR)
	}
	if !prefix.Contains(sandboxCIDR.Addr()) {
		t.Fatalf("sandbox interface prefix = %q, want address within configured pool %q", sandboxCIDR, prefix)
	}
	if strings.Contains(string(hostIPOutput), sandboxCIDR.String()) {
		t.Skipf("host already exposes sandbox address %q; dirty host state", sandboxCIDR)
	}
	if stdout == string(hostIPOutput) {
		t.Fatalf("sandbox ip output matched host network view exactly; stdout=%q", stdout)
	}
}

func TestBoxBuildsDockerfileWithRootlessBuildKit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteBuildKitEnabledConfig(t, binary.ModuleRoot)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-buildkit-smoke.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	inputPath := filepath.Join(contextDir, "hello.txt")
	if err := os.WriteFile(inputPath, []byte("hello from buildkit\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", inputPath, err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM scratch\nCOPY hello.txt /hello.txt\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)

	script := buildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		t.Fatalf("run box buildctl smoke build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v; stdout=%q stderr=%q", filepath.Join(outputDir, "hello.txt"), err, stdout, stderr)
	}
	if string(got) != "hello from buildkit\n" {
		t.Fatalf("built hello.txt = %q, want %q", string(got), "hello from buildkit\n")
	}
}

func TestBoxEnforceBuildsMultistageDockerfile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, nil, []string{"1.1.1.1/32"})

	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-build.")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	outputDir := filepath.Join(contextDir, "out")
	dockerfile := strings.TrimSpace(`
FROM scratch AS fetch-stage
ADD PLACEHOLDER_FIXTURE_URL /build-artifact.txt

FROM scratch
COPY --from=fetch-stage /build-artifact.txt /build-artifact.txt
`) + "\n"
	dockerfile = strings.ReplaceAll(dockerfile, "PLACEHOLDER_FIXTURE_URL", buildKitRemoteFetchURL)
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)
	script := buildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		t.Fatalf("run box enforce buildctl build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "build-artifact.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v; stdout=%q stderr=%q", filepath.Join(outputDir, "build-artifact.txt"), err, stdout, stderr)
	}
	if !strings.Contains(string(got), "h=1.1.1.1") {
		t.Fatalf("build artifact = %q, want Cloudflare trace body", string(got))
	}
}

func TestBoxEnforceBlocksDisallowedRemoteBuildFetch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, nil, nil)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-deny-build.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	dockerfile := strings.TrimSpace(`
FROM scratch
ADD PLACEHOLDER_FIXTURE_URL /blocked.txt
`) + "\n"
	dockerfile = strings.ReplaceAll(dockerfile, "PLACEHOLDER_FIXTURE_URL", buildKitRemoteFetchURL)
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)

	script := buildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err == nil {
		t.Fatalf("expected enforce mode build to fail without explicit remote CIDR allowlist; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxEnforceBuildsDockerfileFromAllowedRegistry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceBuildKitProxyConfig(t, []string{"docker.io", "cloudflarestorage.com"}, nil)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-registry-build.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	dockerfile := strings.TrimSpace(`
FROM docker.io/library/busybox:1.36.1
COPY hello.txt /hello.txt
`) + "\n"
	if err := os.WriteFile(filepath.Join(contextDir, "hello.txt"), []byte("hello from registry build\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filepath.Join(contextDir, "hello.txt"), err)
	}
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)

	script := buildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		t.Fatalf("run box enforce registry-backed buildctl build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v; stdout=%q stderr=%q", filepath.Join(outputDir, "hello.txt"), err, stdout, stderr)
	}
	if string(got) != "hello from registry build\n" {
		t.Fatalf("built hello.txt = %q, want %q", string(got), "hello from registry build\n")
	}
}

func TestBoxEnforceBlocksDockerfileFromDisallowedRegistry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceBuildKitProxyConfig(t, []string{"example.com"}, nil)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-registry-deny-build.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	dockerfile := strings.TrimSpace(`
FROM docker.io/library/busybox:1.36.1
COPY hello.txt /hello.txt
`) + "\n"
	if err := os.WriteFile(filepath.Join(contextDir, "hello.txt"), []byte("hello from denied registry build\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filepath.Join(contextDir, "hello.txt"), err)
	}
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)

	script := buildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err == nil {
		t.Fatalf("expected enforce mode registry-backed build to fail without registry allowlist; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxSandboxedBuildctlBuildAllowsFromAndNetworkedRunUnderPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceBuildKitProxyConfig(t, []string{"docker.io", "cloudflarestorage.com", "example.com"}, nil)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-sandboxed-buildctl-allow.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	dockerfile := strings.TrimSpace(`
FROM docker.io/library/busybox:1.36.1 AS build
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" no_proxy="$NO_PROXY" wget -Y on -qO /run-fetch.txt http://example.com && grep -q 'Example Domain' /run-fetch.txt
COPY hello.txt /hello.txt

FROM scratch
COPY --from=build /hello.txt /hello.txt
COPY --from=build /run-fetch.txt /run-fetch.txt
`) + "\n"
	if err := os.WriteFile(filepath.Join(contextDir, "hello.txt"), []byte("hello from sandboxed buildctl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filepath.Join(contextDir, "hello.txt"), err)
	}
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)
	if err := os.MkdirAll(outputDir, 0o777); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", outputDir, err)
	}
	if err := os.Chmod(outputDir, 0o777); err != nil {
		t.Fatalf("Chmod(%q) error = %v", outputDir, err)
	}

	script := sandboxedBuildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		t.Fatalf("run box sandboxed buildctl allow build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	hello, err := os.ReadFile(filepath.Join(outputDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v; stdout=%q stderr=%q", filepath.Join(outputDir, "hello.txt"), err, stdout, stderr)
	}
	if string(hello) != "hello from sandboxed buildctl\n" {
		t.Fatalf("built hello.txt = %q, want %q", string(hello), "hello from sandboxed buildctl\n")
	}
	runFetch, err := os.ReadFile(filepath.Join(outputDir, "run-fetch.txt"))
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v; stdout=%q stderr=%q", filepath.Join(outputDir, "run-fetch.txt"), err, stdout, stderr)
	}
	if !strings.Contains(string(runFetch), "Example Domain") {
		t.Fatalf("run-fetch.txt = %q, want Example Domain response body", string(runFetch))
	}
}

func TestBoxSandboxedBuildctlBlocksNetworkedRunWithoutAllowlist(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "runsc", "rootlesskit", "newuidmap", "newgidmap", "buildctl", "buildkitd", "nsenter", "setpriv")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceBuildKitProxyConfig(t, []string{"docker.io", "cloudflarestorage.com"}, nil)
	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-sandboxed-buildctl-deny.")
	outputDir := filepath.Join(contextDir, "out")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	dockerfile := strings.TrimSpace(`
FROM docker.io/library/busybox:1.36.1
RUN http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" no_proxy="$NO_PROXY" wget -Y on -qO /run-fetch.txt http://example.com && grep -q 'Example Domain' /run-fetch.txt
COPY hello.txt /hello.txt
`) + "\n"
	if err := os.WriteFile(filepath.Join(contextDir, "hello.txt"), []byte("hello from denied sandboxed buildctl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filepath.Join(contextDir, "hello.txt"), err)
	}
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", dockerfilePath, err)
	}
	chownTreeToOriginalUser(t, contextDir)
	if err := os.MkdirAll(outputDir, 0o777); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", outputDir, err)
	}
	if err := os.Chmod(outputDir, 0o777); err != nil {
		t.Fatalf("Chmod(%q) error = %v", outputDir, err)
	}

	script := sandboxedBuildctlBuildScript(t, binary.ModuleRoot, relPath(t, binary.ModuleRoot, contextDir), relPath(t, binary.ModuleRoot, contextDir), "Dockerfile", relPath(t, binary.ModuleRoot, outputDir))
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err == nil {
		t.Fatalf("expected sandboxed buildctl build to fail when RUN hostname is not allowlisted; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxEnforceBlocksDisallowedTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"docker.io"}, nil)

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
	args := append([]string{"--"}, payload...)
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

func firstNonLoopbackIPv4Prefix(t *testing.T, output string) netip.Prefix {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "inet" {
				continue
			}
			prefix, err := netip.ParsePrefix(fields[i+1])
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			if prefix.Addr().IsLoopback() {
				continue
			}
			return prefix.Masked()
		}
	}

	t.Fatalf("ip output = %q, want non-loopback ipv4 prefix", output)
	return netip.Prefix{}
}

func buildctlBuildScript(t *testing.T, moduleRoot string, contextRel string, dockerfileRel string, filename string, outputRel string) string {
	t.Helper()

	_ = moduleRoot

	script := strings.TrimSpace(`
set -e
buildctl-daemonless.sh build \
  --frontend=dockerfile.v0 \
  --local context=CONTEXT_DIR \
  --local dockerfile=DOCKERFILE_DIR \
  --opt filename=DOCKERFILE_NAME \
  --output type=local,dest=OUTPUT_DEST
`) + "\n"
	script = strings.ReplaceAll(script, "CONTEXT_DIR", shellSingleQuote(contextRel))
	script = strings.ReplaceAll(script, "DOCKERFILE_DIR", shellSingleQuote(dockerfileRel))
	script = strings.ReplaceAll(script, "DOCKERFILE_NAME", shellSingleQuote(filename))
	script = strings.ReplaceAll(script, "OUTPUT_DEST", shellSingleQuote(outputRel))
	return script
}

func sandboxedBuildctlBuildScript(t *testing.T, moduleRoot string, contextRel string, dockerfileRel string, filename string, outputRel string) string {
	t.Helper()

	_ = moduleRoot

	script := strings.TrimSpace(`
set -e
test -n "$BUILDKIT_HOST"
buildctl debug workers >/dev/null
buildctl build \
  --frontend=dockerfile.v0 \
  --local context=CONTEXT_DIR \
  --local dockerfile=DOCKERFILE_DIR \
  --opt filename=DOCKERFILE_NAME \
  --output type=local,dest=OUTPUT_DEST
`) + "\n"
	script = strings.ReplaceAll(script, "CONTEXT_DIR", shellSingleQuote(contextRel))
	script = strings.ReplaceAll(script, "DOCKERFILE_DIR", shellSingleQuote(dockerfileRel))
	script = strings.ReplaceAll(script, "DOCKERFILE_NAME", shellSingleQuote(filename))
	script = strings.ReplaceAll(script, "OUTPUT_DEST", shellSingleQuote(outputRel))
	return script
}

func chownTreeToOriginalUser(t *testing.T, root string) {
	t.Helper()

	uidValue := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidValue := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidValue == "" || gidValue == "" {
		return
	}

	uid, err := strconv.Atoi(uidValue)
	if err != nil {
		t.Fatalf("parse SUDO_UID %q: %v", uidValue, err)
	}
	gid, err := strconv.Atoi(gidValue)
	if err != nil {
		t.Fatalf("parse SUDO_GID %q: %v", gidValue, err)
	}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if info.IsDir() {
			mode = 0o755
		} else if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	}); err != nil {
		t.Fatalf("chown build context %q: %v", root, err)
	}
}
