package integration

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"gvisor-net/integration/testenv"
)

func TestBoxCannotWriteReadOnlyUsr(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "bash", "-lc", "touch /usr/.box-isolation-write-test")
	t.Fatalf("TODO: implement assertion")
}

func TestBoxCanWriteTmp(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "bash", "-lc", "touch /tmp/.box-isolation-write-test")
	t.Fatalf("TODO: implement assertion")
}

func TestBoxCanWriteSandboxWorkdir(t *testing.T) {
	_, _, _ = runBox(t, true, "--", "bash", "-lc", "touch ./.box-isolation-write-test")
	t.Fatalf("TODO: implement assertion")
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

	requireLinuxAndPrivileges(t)
	if requireRoot {
		requireRootIfNeededForIsolation(t)
	}

	binary := testenv.BuildBoxBinary(t)
	return testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, requireRoot, args...)
}

func requireLinuxAndPrivileges(t *testing.T) {
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
