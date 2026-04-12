package testenv

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type BuiltBox struct {
	ModuleRoot string
	BinaryPath string
}

func BuildBoxBinary(t *testing.T) BuiltBox {
	t.Helper()

	moduleRoot, err := moduleRootFromWorkingDir()
	if err != nil {
		t.Fatalf("moduleRootFromWorkingDir() error = %v", err)
	}

	output := filepath.Join(t.TempDir(), "box")
	if runtime.GOOS == "windows" {
		output += ".exe"
	}
	initShimOutput := filepath.Join(filepath.Dir(output), "box-initshim")
	if runtime.GOOS == "windows" {
		initShimOutput += ".exe"
	}

	if err := buildPackageAt(moduleRoot, "./cmd/box", output); err != nil {
		t.Fatalf("buildPackageAt() error = %v", err)
	}
	if err := buildPackageAt(moduleRoot, "./internal/initshim", initShimOutput); err != nil {
		t.Fatalf("buildPackageAt() error = %v", err)
	}

	return BuiltBox{
		ModuleRoot: moduleRoot,
		BinaryPath: output,
	}
}

func RunBinary(moduleRoot, binaryPath string, requireRoot bool, args ...string) (stdout string, stderr string, err error) {
	fullArgs := append([]string{binaryPath}, args...)
	if requireRoot && os.Geteuid() != 0 {
		if _, lookErr := exec.LookPath("sudo"); lookErr != nil {
			return "", "", fmt.Errorf("sudo is required to run integration command as root: %w", lookErr)
		}
		fullArgs = append([]string{"-E"}, fullArgs...)
		fullArgs = append([]string{"sudo"}, fullArgs...)
	}

	cmd := exec.Command(fullArgs[0], fullArgs[1:]...)
	cmd.Dir = moduleRoot

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	out := outBuf.String()
	errOut := errBuf.String()
	if runErr != nil {
		return out, errOut, fmt.Errorf("run command %q: %w", strings.Join(fullArgs, " "), runErr)
	}
	return out, errOut, nil
}

func RequireCommands(t *testing.T, names ...string) {
	t.Helper()

	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s not available: %v", name, err)
		}
	}
}

func RequireAnyCommand(t *testing.T, names ...string) {
	t.Helper()

	for _, name := range names {
		if _, err := exec.LookPath(name); err == nil {
			return
		}
	}
	t.Skipf("none of the required commands are available: %s", strings.Join(names, ", "))
}

func WriteEnforceConfig(t *testing.T, allowDomains []string, extraAllowedCIDRs []string) string {
	t.Helper()
	subnet := uniqueTestSubnet(t)

	policySection := "  policy: []"
	if len(allowDomains) > 0 || len(extraAllowedCIDRs) > 0 {
		var b strings.Builder
		b.WriteString("  policy:\n")
		for _, domain := range allowDomains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			fmt.Fprintf(&b, "    - hostname: %s\n      ports: [80, 443]\n", domain)
		}
		for _, cidr := range extraAllowedCIDRs {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			fmt.Fprintf(&b, "    - cidr: %s\n      ports: [80, 443]\n", cidr)
		}
		policySection = strings.TrimRight(b.String(), "\n")
	}

	content := fmt.Sprintf(`sandbox:
  rootfs: host-overlay
  rootfs_source: ""
  hostname: box
  workdir: .
  workdir_overlay: false
  env:
    - TERM=xterm
  command_shell: /bin/bash -lc
network:
  mode: enforce
  subnet: %s
  dns:
    bind_addr: auto
    upstream:
      - 1.1.1.1:53
      - 8.8.8.8:53
  envoy:
    enabled: true
    mode: peek
    http_port: 18080
    tls_port: 18443
%s
mounts:
  extra_ro: []
  extra_rw: []
gvisor:
  platform: systrap
  network: sandbox
  debug: false
`, subnet, policySection)

	path := filepath.Join(t.TempDir(), "box-enforce.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}

func WriteWorkdirOverlayConfig(t *testing.T, moduleRoot string, enabled bool) string {
	t.Helper()

	sourcePath := filepath.Join(moduleRoot, "box.yaml")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", sourcePath, err)
	}

	content := string(data)
	if strings.Contains(content, "workdir_overlay: true") {
		if !enabled {
			content = strings.Replace(content, "workdir_overlay: true", "workdir_overlay: false", 1)
		}
	} else if strings.Contains(content, "workdir_overlay: false") {
		if enabled {
			content = strings.Replace(content, "workdir_overlay: false", "workdir_overlay: true", 1)
		}
	} else if strings.Contains(content, "workdir: .") {
		replacement := "workdir: .\n  workdir_overlay: false"
		if enabled {
			replacement = "workdir: .\n  workdir_overlay: true"
		}
		content = strings.Replace(content, "workdir: .", replacement, 1)
	} else {
		t.Fatalf("config template missing sandbox.workdir setting")
	}

	path := filepath.Join(t.TempDir(), "box-workdir-overlay.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}

func WriteOpenCodeMonitorConfig(t *testing.T, hostBinDir string, hostPath string) string {
	t.Helper()

	hostBinDir = strings.TrimSpace(hostBinDir)
	if hostBinDir == "" {
		t.Fatal("hostBinDir is empty")
	}
	if !filepath.IsAbs(hostBinDir) {
		t.Fatalf("hostBinDir must be absolute, got %q", hostBinDir)
	}
	hostPath = strings.TrimSpace(hostPath)
	if hostPath == "" {
		t.Fatal("hostPath is empty")
	}
	subnet := uniqueTestSubnet(t)

	content := fmt.Sprintf(`sandbox:
  rootfs: host-overlay
  rootfs_source: ""
  hostname: box
  workdir: .
  workdir_overlay: true
  inherit_env: true
  env:
    - TERM=xterm
    - PATH=%s
    - HOME=/tmp/opencode-home
    - XDG_CONFIG_HOME=/tmp/opencode-config
    - XDG_DATA_HOME=/tmp/opencode-data
    - XDG_CACHE_HOME=/tmp/opencode-cache
    - NODE_EXTRA_CA_CERTS=
  command_shell: /bin/bash -lc
network:
  mode: monitor
  subnet: %s
  dns:
    bind_addr: auto
    upstream:
      - 1.1.1.1:53
      - 8.8.8.8:53
  envoy:
    enabled: true
    mode: peek
    http_port: 18080
    tls_port: 18443
  policy: []
mounts:
  extra_ro:
    - %s
  extra_rw: []
gvisor:
  platform: systrap
  network: sandbox
  debug: false
`, hostPath, subnet, hostBinDir)

	path := filepath.Join(t.TempDir(), "box-opencode-monitor.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}

func buildPackage(pkgPath, output string) error {
	moduleRoot, err := moduleRootFromWorkingDir()
	if err != nil {
		return err
	}
	return buildPackageAt(moduleRoot, pkgPath, output)
}

func uniqueTestSubnet(t *testing.T) string {
	t.Helper()

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(t.Name()))
	thirdOctet := 1 + int(hasher.Sum32()%250)
	return fmt.Sprintf("100.96.%d.0/24", thirdOctet)
}

func buildPackageAt(moduleRoot, pkgPath, output string) error {
	args := goBuildArgs(pkgPath, output)
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot

	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build %s: %w: %s", pkgPath, err, strings.TrimSpace(string(outputBytes)))
	}
	return nil
}

func goBuildArgs(pkgPath, output string) []string {
	return []string{"build", "-buildvcs=false", "-o", output, pkgPath}
}

func moduleRootFromWorkingDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("determine working directory: %w", err)
	}
	return findModuleRoot(cwd)
}

func findModuleRoot(start string) (string, error) {
	if strings.TrimSpace(start) == "" {
		return "", fmt.Errorf("start path is empty")
	}

	abs, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve start path %q: %w", start, err)
	}

	current := abs
	info, err := os.Stat(current)
	if err != nil {
		return "", fmt.Errorf("stat start path %q: %w", current, err)
	}
	if !info.IsDir() {
		current = filepath.Dir(current)
	}

	for {
		goMod := filepath.Join(current, "go.mod")
		if stat, statErr := os.Stat(goMod); statErr == nil && !stat.IsDir() {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("go.mod not found from %q", start)
		}
		current = parent
	}
}

func yamlList(values []string, indent string) string {
	if len(values) == 0 {
		return indent + "[]"
	}

	lines := make([]string, 0, len(values))
	for _, value := range values {
		lines = append(lines, indent+"- "+value)
	}
	return strings.Join(lines, "\n")
}
