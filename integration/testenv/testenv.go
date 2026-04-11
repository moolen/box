package testenv

import (
	"bytes"
	"fmt"
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

func buildPackage(pkgPath, output string) error {
	moduleRoot, err := moduleRootFromWorkingDir()
	if err != nil {
		return err
	}
	return buildPackageAt(moduleRoot, pkgPath, output)
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
