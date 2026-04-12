package gvisor

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

type RunRequest struct {
	BundleDir   string
	ContainerID string
	NetNS       string
}

type CommandRunner interface {
	Run(name string, args ...string) error
}

type Runner struct {
	Command CommandRunner
	Binary  string
}

func (r Runner) Run(req RunRequest) error {
	if strings.TrimSpace(req.BundleDir) == "" {
		return errors.New("bundle dir is required")
	}
	if strings.TrimSpace(req.ContainerID) == "" {
		return errors.New("container id is required")
	}

	binary := strings.TrimSpace(r.Binary)
	if binary == "" {
		binary = "runsc"
	}

	command := r.Command
	if command == nil {
		command = ExecCommandRunner{}
	}

	args := []string{"--ignore-cgroups", "run", "--bundle", req.BundleDir, req.ContainerID}
	if strings.TrimSpace(req.NetNS) != "" {
		ipArgs := []string{"netns", "exec", strings.TrimSpace(req.NetNS), binary}
		ipArgs = append(ipArgs, args...)
		return command.Run("ip", ipArgs...)
	}
	return command.Run(binary, args...)
}

func netNSPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "/") {
		return name
	}
	return "/run/netns/" + name
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
