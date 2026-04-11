package integration

import (
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

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
