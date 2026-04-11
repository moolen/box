package integration

import (
	"fmt"
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
	expectedSandboxIP := prefix.Masked().Addr().Next().Next()
	expectedCIDR := expectedSandboxIP.String() + "/" + strconv.Itoa(prefix.Bits())

	hostIPOutput, err := exec.Command("ip", "-4", "-o", "addr", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("host ip command error = %v: %s", err, strings.TrimSpace(string(hostIPOutput)))
	}
	if strings.Contains(string(hostIPOutput), expectedCIDR) {
		t.Skipf("host already exposes expected sandbox address %q; dirty host state", expectedCIDR)
	}

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--", "ip", "-4", "-o", "addr", "show")
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
	configPath := testenv.WriteEnforceConfig(t, []string{
		"debian.org",
		"alpinelinux.org",
		"npmjs.org",
		"registry.npmjs.org",
	}, nil)

	contextDir := mustMakeModuleTempDir(t, binary.ModuleRoot, ".box-enforce-build.")
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")
	alpineArchivePath := filepath.Join(contextDir, "alpine.tar")
	debianArchivePath := filepath.Join(contextDir, "debian.tar")
	dockerfile := strings.TrimSpace(`
FROM alpine:3.20 AS alpine-stage
RUN apk add --no-cache curl
RUN curl -fsSL http://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz >/dev/null

FROM debian:bookworm-slim AS debian-stage
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates npm
WORKDIR /tmp/app
RUN npm init -y >/dev/null && npm install is-number --ignore-scripts
RUN curl -fsSL https://registry.npmjs.org/is-number >/dev/null

FROM debian:bookworm-slim
COPY --from=alpine-stage /etc/alpine-release /alpine-release
COPY --from=debian-stage /tmp/app/package.json /package.json
CMD ["cat", "/alpine-release"]
`) + "\n"
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
`, shellSingleQuote(relPath(t, binary.ModuleRoot, alpineArchivePath)), shellSingleQuote(relPath(t, binary.ModuleRoot, debianArchivePath)), shellSingleQuote(imageTag), shellSingleQuote(relPath(t, binary.ModuleRoot, dockerfilePath)), shellSingleQuote(relPath(t, binary.ModuleRoot, contextDir)), shellSingleQuote(imageTag))

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "bash", "-lc", script)
	if err != nil {
		t.Fatalf("run box enforce docker build error = %v; stdout=%q stderr=%q", err, stdout, stderr)
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
