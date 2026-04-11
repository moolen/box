package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gvisor-net/integration/testenv"
)

func TestBoxCannotWriteReadOnlyUsr(t *testing.T) {
	const sentinel = "/usr/.box-write-test"

	_, stderr, err := runBox(t, true, "--", "bash", "-lc", "printf x >/usr/.box-write-test")
	if err == nil {
		_ = os.Remove(sentinel)
		t.Fatalf("expected write to /usr to fail; stderr=%q", stderr)
	}
	lowerStderr := strings.ToLower(stderr)
	if !strings.Contains(lowerStderr, "read-only file system") && !strings.Contains(lowerStderr, "permission denied") {
		t.Fatalf("expected readonly or permission error for /usr write, got stderr=%q", stderr)
	}
}

func TestBoxCanWriteTmp(t *testing.T) {
	stdout, stderr, err := runBox(t, true, "--", "bash", "-lc", "p=$(mktemp /tmp/box.XXXXXX) && printf isolated >\"$p\" && cat \"$p\" && rm -f \"$p\"")
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
	workdir := t.TempDir()
	if err := os.Chmod(workdir, 0o777); err != nil {
		t.Fatalf("Chmod(%q) error = %v", workdir, err)
	}

	sentinel := fmt.Sprintf(".box-workdir-write-test.%d", time.Now().UnixNano())
	hostPath := filepath.Join(workdir, sentinel)

	command := fmt.Sprintf("printf isolated >%q", sentinel)
	configPath := filepath.Join(binary.ModuleRoot, "box.yaml")
	args := []string{binary.BinaryPath, "--config", configPath, "--", "bash", "-lc", command}
	if os.Geteuid() != 0 {
		args = append([]string{"sudo", "-E"}, args...)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = workdir

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		stderr := stderrBuf.String()
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
	stdout, stderr, err := runBox(t, true, "--", "cat", "/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("cat /proc/self/mountinfo failed: %v stderr=%q", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var foundUsr bool
	var foundTmp bool
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		sep := slices.Index(fields, "-")
		if sep == -1 || sep+3 > len(fields) {
			continue
		}

		mountPoint := fields[4]
		mountOptions := strings.Split(fields[5], ",")
		fsType := fields[sep+1]

		if mountPoint == "/usr" {
			foundUsr = true
			if !slices.Contains(mountOptions, "ro") {
				t.Fatalf("expected /usr mount options to include ro, got line=%q", line)
			}
		}

		if mountPoint == "/tmp" {
			foundTmp = true
			if fsType != "tmpfs" {
				t.Fatalf("expected /tmp fs type tmpfs, got %q line=%q", fsType, line)
			}
			if !slices.Contains(mountOptions, "rw") {
				t.Fatalf("expected /tmp mount options to include rw, got line=%q", line)
			}
		}
	}

	if !foundUsr {
		t.Fatalf("did not find /usr mount in mountinfo")
	}
	if !foundTmp {
		t.Fatalf("did not find /tmp mount in mountinfo")
	}
}

func TestBoxDefaultSandboxCannotMountTmpfs(t *testing.T) {
	_, stderr, err := runBox(t, true, "--", "bash", "-lc", "d=$(mktemp -d /tmp/box-mount-test.XXXXXX) && mount -t tmpfs tmpfs \"$d\"")
	if err == nil {
		t.Fatalf("expected tmpfs mount to fail in default sandbox")
	}
	lowerStderr := strings.ToLower(stderr)
	if !strings.Contains(lowerStderr, "operation not permitted") &&
		!strings.Contains(lowerStderr, "permission denied") &&
		!strings.Contains(lowerStderr, "not allowed") &&
		!strings.Contains(lowerStderr, "must be superuser") {
		t.Fatalf("expected permission error when mounting tmpfs, got stderr=%q", stderr)
	}
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
