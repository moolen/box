package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var wait4 = syscall.Wait4
var listChildPIDs = procChildren

const (
	envDockerEnabled    = "BOX_DOCKER_ENABLED"
	envDockerSocketPath = "BOX_DOCKER_SOCKET_PATH"
	envDockerWait       = "BOX_DOCKER_WAIT_FOR_SOCKET"
	envDockerReady      = "BOX_DOCKER_READY_TIMEOUT"
)

type dockerRuntime struct {
	Enabled       bool
	SocketPath    string
	WaitForSocket bool
	ReadyTimeout  time.Duration
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: box-initshim <command> [args...]")
		os.Exit(127)
	}

	dockerCfg, err := loadDockerRuntime(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load docker runtime: %v\n", err)
		os.Exit(127)
	}

	var dockerCmd *exec.Cmd
	if dockerCfg.Enabled {
		if err := ensureDockerRuntimeDirs(dockerCfg.SocketPath); err != nil {
			fmt.Fprintf(os.Stderr, "prepare docker runtime dirs: %v\n", err)
			os.Exit(127)
		}

		dockerCmd = exec.Command("dockerd")
		dockerCmd.Stdout = os.Stdout
		dockerCmd.Stderr = os.Stderr
		dockerCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		if err := dockerCmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start dockerd: %v\n", err)
			os.Exit(127)
		}
		if dockerCfg.WaitForSocket {
			if err := waitForUnixSocket(dockerCfg.SocketPath, dockerCfg.ReadyTimeout); err != nil {
				stopProcess(dockerCmd, syscall.SIGTERM)
				_ = dockerCmd.Wait()
				reapAllChildren()
				fmt.Fprintf(os.Stderr, "wait for dockerd socket %s: %v\n", dockerCfg.SocketPath, err)
				os.Exit(127)
			}
		}
	}

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start payload: %v\n", err)
		os.Exit(127)
	}

	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh)

	done := make(chan struct{})
	mainPID := cmd.Process.Pid
	dockerPID := 0
	if dockerCmd != nil && dockerCmd.Process != nil {
		dockerPID = dockerCmd.Process.Pid
	}
	go func() {
		defer close(done)
		for sig := range sigCh {
			if sig == syscall.SIGCHLD {
				reapChildrenExceptPIDs(mainPID, dockerPID)
				continue
			}

			sysSig, ok := sig.(syscall.Signal)
			if !ok {
				continue
			}

			// Forward to the payload process group first, then to the process.
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, sysSig)
				_ = cmd.Process.Signal(sig)
			}
			if dockerCmd != nil && dockerCmd.Process != nil {
				_ = syscall.Kill(-dockerCmd.Process.Pid, sysSig)
				_ = dockerCmd.Process.Signal(sig)
			}
		}
	}()

	err = cmd.Wait()
	if dockerCmd != nil {
		stopProcess(dockerCmd, syscall.SIGTERM)
		_ = dockerCmd.Wait()
	}
	reapAllChildren()
	signal.Stop(sigCh)
	close(sigCh)
	<-done
	exitWithErr(err)
}

func reapChildrenExcept(mainPID int) {
	reapChildrenExceptPIDs(mainPID)
}

func reapChildrenExceptPIDs(skipPIDs ...int) {
	children, err := listChildPIDs()
	if err != nil {
		return
	}
	skip := make(map[int]struct{}, len(skipPIDs))
	for _, pid := range skipPIDs {
		if pid > 0 {
			skip[pid] = struct{}{}
		}
	}
	for _, pid := range children {
		if _, ok := skip[pid]; ok {
			continue
		}
		reapPID(pid)
	}
}

func reapAllChildren() {
	for {
		var status syscall.WaitStatus
		pid, err := wait4(-1, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err == nil {
			if pid == 0 {
				return
			}
			continue
		}
		if errors.Is(err, syscall.ECHILD) {
			return
		}
		return
	}
}

func reapPID(pid int) {
	for {
		var status syscall.WaitStatus
		reapedPID, err := wait4(pid, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err == nil {
			if reapedPID == 0 {
				return
			}
			continue
		}
		if errors.Is(err, syscall.ECHILD) {
			return
		}
		return
	}
}

func procChildren() ([]int, error) {
	data, err := os.ReadFile("/proc/self/task/self/children")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	out := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		out = append(out, pid)
	}
	return out, nil
}

func loadDockerRuntime(getenv func(string) string) (dockerRuntime, error) {
	cfg := dockerRuntime{
		SocketPath:    "/var/run/docker.sock",
		WaitForSocket: true,
		ReadyTimeout:  10 * time.Second,
	}
	if value := strings.TrimSpace(getenv(envDockerEnabled)); value == "" || value == "0" {
		return dockerRuntime{}, nil
	}
	cfg.Enabled = true

	if value := strings.TrimSpace(getenv(envDockerSocketPath)); value != "" {
		cfg.SocketPath = value
	}
	if value := strings.TrimSpace(getenv(envDockerWait)); value != "" {
		cfg.WaitForSocket = value != "0" && !strings.EqualFold(value, "false")
	}
	if value := strings.TrimSpace(getenv(envDockerReady)); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return dockerRuntime{}, fmt.Errorf("parse %s: %w", envDockerReady, err)
		}
		cfg.ReadyTimeout = timeout
	}
	return cfg, nil
}

func waitForUnixSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func ensureDockerRuntimeDirs(socketPath string) error {
	socketDir := filepath.Dir(strings.TrimSpace(socketPath))
	if socketDir == "." || socketDir == "" {
		socketDir = "/var/run"
	}
	runtimeDir := filepath.Join(socketDir, "docker")
	for _, dir := range []string{
		runtimeDir,
		filepath.Join(runtimeDir, "containerd"),
		filepath.Join(runtimeDir, "libnetwork"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func stopProcess(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, sig)
	_ = cmd.Process.Signal(sig)
}

func exitWithErr(err error) {
	if err == nil {
		os.Exit(0)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				os.Exit(128 + int(status.Signal()))
			}
			os.Exit(status.ExitStatus())
		}
	}
	fmt.Fprintf(os.Stderr, "wait payload: %v\n", err)
	os.Exit(1)
}
