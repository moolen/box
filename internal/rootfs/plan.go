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
	optionalReadonlyBinds = []string{"/etc/alternatives", "/etc/ca-certificates", "/etc/pki", "/etc/ssl", "/opt", "/snap", "/nix"}
	writableRuntimeDirs   = []string{"/tmp", "/var/tmp", "/run", "/var/run", "/var/cache"}
)

const RuntimeCACertPath = "/etc/box/ca-certificates/runtime-ca.crt"

type PlanRequest struct {
	RootfsMode        string
	RepoPath          string
	Workdir           string
	NetworkMode       string
	GatewayIP         string
	SandboxHostn      string
	ExtraRO           []string
	ExtraRW           []string
	RuntimeCACertPEM  string
	TrustedCACertPEM  string
	TrustedCACertPath string
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
	WritableDirs   []string
	WritableOwners map[string]DirOwner
}

type DirOwner struct {
	UID int
	GID int
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
		WritableDirs:   append([]string(nil), writableRuntimeDirs...),
		WritableOwners: make(map[string]DirOwner),
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

	if strings.TrimSpace(req.RepoPath) != "" && strings.TrimSpace(req.Workdir) != "" {
		plan.Binds = append(plan.Binds, Bind{
			Source:   req.RepoPath,
			Target:   req.Workdir,
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
	if usesGatewayDNS(req.NetworkMode) && strings.TrimSpace(req.GatewayIP) != "" {
		nameserver = strings.TrimSpace(req.GatewayIP)
	}

	files := []GeneratedFile{
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
	trustedPEM := req.TrustedCACertPEM
	trustedPath := strings.TrimSpace(req.TrustedCACertPath)
	if strings.TrimSpace(trustedPEM) != "" {
		if trustedPath == "" {
			trustedPath = RuntimeCACertPath
		}
		files = append(files, GeneratedFile{
			Path:    trustedPath,
			Content: trustedPEM,
			Mode:    0o644,
		})
	} else if strings.TrimSpace(req.RuntimeCACertPEM) != "" {
		files = append(files, GeneratedFile{
			Path:    RuntimeCACertPath,
			Content: req.RuntimeCACertPEM,
			Mode:    0o644,
		})
	}
	return files
}

func usesGatewayDNS(mode string) bool {
	mode = strings.TrimSpace(mode)
	return strings.EqualFold(mode, "monitor") || strings.EqualFold(mode, "enforce")
}
