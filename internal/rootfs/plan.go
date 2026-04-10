package rootfs

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

var (
	requiredReadonlyBinds = []string{"/bin", "/sbin", "/usr", "/lib", "/lib64"}
	optionalReadonlyBinds = []string{"/etc/alternatives", "/opt", "/snap", "/nix"}
	writableRuntimeDirs   = []string{"/tmp", "/var/tmp", "/run", "/var/run", "/var/cache"}
)

type PlanRequest struct {
	RootfsMode     string
	RepoPath       string
	Workdir        string
	NetworkMode    string
	GatewayIP      string
	SandboxHostn   string
	DockerEnabled  bool
	DockerDataRoot string
	ExtraRO        []string
	ExtraRW        []string
}

type Bind struct {
	Source   string
	Target   string
	ReadOnly bool
}

type GeneratedFile struct {
	Path    string
	Content string
	Mode    os.FileMode
}

type Plan struct {
	Binds          []Bind
	GeneratedFiles []GeneratedFile
}

func BuildPlan(req PlanRequest) (Plan, error) {
	mode := strings.TrimSpace(req.RootfsMode)
	if mode == "" {
		return Plan{}, errors.New("rootfs mode is required")
	}
	if mode != "host-overlay" && mode != "image" {
		return Plan{}, fmt.Errorf("unsupported rootfs mode %q", mode)
	}

	plan := Plan{
		Binds:          make([]Bind, 0, 24),
		GeneratedFiles: generatedEtcFiles(req),
	}

	if mode != "host-overlay" {
		return plan, nil
	}

	for _, src := range requiredReadonlyBinds {
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
	}
	for _, src := range optionalReadonlyBinds {
		if _, err := os.Stat(src); err == nil {
			plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
		}
	}
	for _, path := range writableRuntimeDirs {
		plan.Binds = append(plan.Binds, Bind{Source: path, Target: path, ReadOnly: false})
	}

	if strings.TrimSpace(req.RepoPath) != "" && strings.TrimSpace(req.Workdir) != "" {
		plan.Binds = append(plan.Binds, Bind{
			Source:   req.RepoPath,
			Target:   req.Workdir,
			ReadOnly: false,
		})
	}

	if req.DockerEnabled && strings.TrimSpace(req.DockerDataRoot) != "" {
		plan.Binds = append(plan.Binds, Bind{
			Source:   req.DockerDataRoot,
			Target:   req.DockerDataRoot,
			ReadOnly: false,
		})
	}

	for _, src := range req.ExtraRO {
		src = strings.TrimSpace(src)
		if src == "" || slices.Contains(requiredReadonlyBinds, src) {
			continue
		}
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
	}
	for _, src := range req.ExtraRW {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: false})
	}

	return plan, nil
}

func generatedEtcFiles(req PlanRequest) []GeneratedFile {
	hostname := strings.TrimSpace(req.SandboxHostn)
	if hostname == "" {
		hostname = "box"
	}

	nameserver := "127.0.0.1"
	if req.NetworkMode == "monitor" && strings.TrimSpace(req.GatewayIP) != "" {
		nameserver = strings.TrimSpace(req.GatewayIP)
	}

	return []GeneratedFile{
		{
			Path:    "/etc/resolv.conf",
			Content: "nameserver " + nameserver + "\noptions ndots:0\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/hosts",
			Content: "127.0.0.1 localhost\n127.0.1.1 " + hostname + "\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/hostname",
			Content: hostname + "\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/passwd",
			Content: "root:x:0:0:root:/root:/bin/sh\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/group",
			Content: "root:x:0:\n",
			Mode:    0o644,
		},
	}
}
