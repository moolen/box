package envoy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	BundledVersion          = "v1.37.1"
	BundledImageRef         = "docker.io/envoyproxy/envoy@sha256:4d9226b9fd4d1449887de7cde785beb24b12e47d6e79021dec3c79e362609432"
	BundledPlatformImageRef = "docker.io/envoyproxy/envoy:distroless-" + BundledVersion
	bundledBinaryInImage    = "/usr/local/bin/envoy"
)

type RuntimeLocator struct {
	LookPath func(string) (string, error)
}

type StageRequest struct {
	OutputPath string
	Runtime    string
	Platform   string
	Run        func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func ResolveContainerRuntime(locator RuntimeLocator) (string, error) {
	lookPath := locator.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	for _, candidate := range []string{"docker", "podman"} {
		if _, err := lookPath(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", errors.New("no supported container runtime found; install docker or podman to stage bundled envoy")
}

func StageBundledBinary(ctx context.Context, req StageRequest) error {
	outputPath := strings.TrimSpace(req.OutputPath)
	if outputPath == "" {
		return errors.New("output path is required")
	}

	runtimeName := strings.TrimSpace(req.Runtime)
	if runtimeName == "" {
		resolved, err := ResolveContainerRuntime(RuntimeLocator{})
		if err != nil {
			return err
		}
		runtimeName = resolved
	}

	run := req.Run
	if run == nil {
		run = runOutput
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output dir for %q: %w", outputPath, err)
	}

	if currentVersion, err := binaryVersion(ctx, run, outputPath); err == nil && versionMatches(currentVersion) {
		return nil
	}

	tempPath := outputPath + ".tmp"
	_ = os.Remove(tempPath)
	defer func() {
		_ = os.Remove(tempPath)
	}()

	createArgs := []string{"create"}
	imageRef := BundledImageRef
	if platform := strings.TrimSpace(req.Platform); platform != "" {
		createArgs = append(createArgs, "--platform", platform)
		imageRef = BundledPlatformImageRef
	}
	createArgs = append(createArgs, imageRef)

	containerIDBytes, err := run(ctx, runtimeName, createArgs...)
	if err != nil {
		return commandError(fmt.Sprintf("create container from %s", imageRef), containerIDBytes, err)
	}
	containerID := parseContainerID(containerIDBytes)
	if containerID == "" {
		return errors.New("container runtime returned empty container id while staging bundled envoy")
	}
	defer func() {
		_, _ = run(context.Background(), runtimeName, "rm", "-f", containerID)
	}()

	if copyOutput, err := run(ctx, runtimeName, "cp", containerID+":"+bundledBinaryInImage, tempPath); err != nil {
		return commandError(fmt.Sprintf("copy envoy binary from %s", imageRef), copyOutput, err)
	}
	if err := os.Chmod(tempPath, 0o755); err != nil {
		return fmt.Errorf("chmod staged envoy binary %q: %w", tempPath, err)
	}

	version, err := binaryVersion(ctx, run, tempPath)
	if err != nil {
		return fmt.Errorf("inspect staged envoy binary %q: %w", tempPath, err)
	}
	if !versionMatches(version) {
		return fmt.Errorf("staged envoy version %q does not match pinned version %s", version, BundledVersion)
	}

	if err := os.Rename(tempPath, outputPath); err != nil {
		return fmt.Errorf("move staged envoy binary to %q: %w", outputPath, err)
	}
	return nil
}

func binaryVersion(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error), binaryPath string) (string, error) {
	output, err := run(ctx, binaryPath, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func versionMatches(output string) bool {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return false
	}
	for _, candidate := range []string{BundledVersion, strings.TrimPrefix(BundledVersion, "v")} {
		if candidate != "" && strings.Contains(trimmed, candidate) {
			return true
		}
	}
	return false
}

func runOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func commandError(action string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, message)
}

func parseContainerID(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}
