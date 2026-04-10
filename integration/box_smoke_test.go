package integration

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"gvisor-net/integration/testenv"
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
