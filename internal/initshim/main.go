package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var wait4 = syscall.Wait4
var listChildPIDs = procChildren

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: box-initshim <command> [args...]")
		os.Exit(127)
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
	go func() {
		defer close(done)
		for sig := range sigCh {
			if sig == syscall.SIGCHLD {
				reapChildrenExceptPIDs(mainPID)
				continue
			}

			sysSig, ok := sig.(syscall.Signal)
			if !ok {
				continue
			}

			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, sysSig)
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	err := cmd.Wait()
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
