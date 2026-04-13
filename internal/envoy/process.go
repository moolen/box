package envoy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type BinaryLocator struct {
	ExecutablePath string
	FileExists     func(path string) bool
}

type StartRequest struct {
	BinaryPath    string
	BootstrapPath string
	LogPath       string
}

type Process struct {
	cmd      *exec.Cmd
	waitOnce sync.Once
	waitErr  error
}

func ResolveBinary(locator BinaryLocator) (string, error) {
	executablePath := strings.TrimSpace(locator.ExecutablePath)
	if executablePath == "" {
		return "", errors.New("executable path is required")
	}

	fileExists := locator.FileExists
	if fileExists == nil {
		fileExists = func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && !info.IsDir()
		}
	}

	sibling := filepath.Join(filepath.Dir(executablePath), "envoy")
	if fileExists(sibling) {
		return sibling, nil
	}

	return "", fmt.Errorf("bundled envoy binary not found next to %q", executablePath)
}

func Args(req StartRequest) ([]string, error) {
	if strings.TrimSpace(req.BinaryPath) == "" {
		return nil, errors.New("binary path is required")
	}
	if strings.TrimSpace(req.BootstrapPath) == "" {
		return nil, errors.New("bootstrap path is required")
	}

	args := []string{
		"-c", req.BootstrapPath,
		"--disable-hot-restart",
	}
	if strings.TrimSpace(req.LogPath) != "" {
		args = append(args, "--log-path", req.LogPath)
	}
	return args, nil
}

func Start(ctx context.Context, req StartRequest) (*Process, error) {
	args, err := Args(req)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, req.BinaryPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start envoy: %w", err)
	}
	return &Process{cmd: cmd}, nil
}

func (p *Process) Stop() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}

	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	p.wait()
	return nil
}

func (p *Process) wait() error {
	if p == nil || p.cmd == nil {
		return nil
	}
	p.waitOnce.Do(func() {
		p.waitErr = p.cmd.Wait()
	})
	return p.waitErr
}
