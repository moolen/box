package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor-net/integration/testenv"
)

func TestBoxCannotWriteReadOnlyUsr(t *testing.T) {
	_, stderr, err := runBox(t, true, "--", "bash", "-lc", "printf x >/usr/.box-write-test")
	if err == nil {
		t.Fatalf("expected write to /usr to fail; stderr=%q", stderr)
	}
}

func TestBoxCanWriteTmp(t *testing.T) {
	stdout, stderr, err := runBox(t, true, "--", "bash", "-lc", "p=$(mktemp /tmp/box.XXXXXX) && printf isolated >\"$p\" && cat \"$p\"")
	if err != nil {
		t.Fatalf("tmp write failed: %v stderr=%q", err, stderr)
	}
	if strings.TrimSpace(stdout) != "isolated" {
		t.Fatalf("stdout=%q want %q", stdout, "isolated")
	}
}

func TestBoxCanWriteSandboxWorkdir(t *testing.T) {
	requireLinuxForIsolation(t)
	requireRootIfNeededForIsolation(t)

	binary := testenv.BuildBoxBinary(t)

	sentinel := fmt.Sprintf(".box-workdir-write-test.%d", time.Now().UnixNano())
	hostPath := filepath.Join(binary.ModuleRoot, sentinel)
	t.Cleanup(func() {
		_ = os.Remove(hostPath)
	})

	command := fmt.Sprintf("printf isolated >%q", sentinel)
	if _, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--", "bash", "-lc", command); err != nil {
		t.Fatalf("workdir write failed: %v stderr=%q", err, stderr)
	}

	data, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", hostPath, err)
	}
	if strings.TrimSpace(string(data)) != "isolated" {
		t.Fatalf("host file content=%q want %q", string(data), "isolated")
	}
}

func TestBoxMountInfoShowsUsrReadOnlyAndTmpfsTmp(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "cat", "/proc/self/mountinfo")
	t.Fatalf("TODO: implement assertion")
}

func TestBoxDefaultPrivilegeSurfaceDoesNotLookDockerElevated(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "bash", "-lc", "id -u; capsh --print")
	t.Fatalf("TODO: implement assertion")
}

func TestBoxDefaultSandboxCannotMountTmpfs(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "bash", "-lc", "mkdir -p /tmp/box-mount-test && mount -t tmpfs tmpfs /tmp/box-mount-test")
	t.Fatalf("TODO: implement assertion")
}

func runBox(t *testing.T, requireRoot bool, args ...string) (string, string, error) {
	t.Helper()

	requireLinuxForIsolation(t)
	if requireRoot {
		requireRootIfNeededForIsolation(t)
	}

	binary := testenv.BuildBoxBinary(t)
	return testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, requireRoot, args...)
}

func requireLinuxForIsolation(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("integration isolation tests require Linux")
	}
}

func requireRootIfNeededForIsolation(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		return
	}

	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skipf("sudo not available for root-required isolation tests: %v", err)
	}

	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("sudo privileges are required for isolation tests: %v", err)
	}
}
