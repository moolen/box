package rootfs

import (
	"encoding/json"
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

type PlanRequest struct {
	RootfsMode       string
	RepoPath         string
	Workdir          string
	NetworkMode      string
	GatewayIP        string
	SandboxHostn     string
	DockerEnabled    bool
	DockerDataRoot   string
	DockerSocketPath string
	DockerHTTPProxy  string
	DockerHTTPSProxy string
	DockerNoProxy    string
	ExtraRO          []string
	ExtraRW          []string
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
		WritableDirs:   make([]string, 0, 8),
	}

	for _, path := range writableRuntimeDirs {
		plan.WritableDirs = appendUniquePath(plan.WritableDirs, path)
	}
	if req.DockerEnabled && strings.TrimSpace(req.DockerDataRoot) != "" {
		plan.WritableDirs = appendUniquePath(plan.WritableDirs, strings.TrimSpace(req.DockerDataRoot))
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

func appendUniquePath(paths []string, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" || slices.Contains(paths, path) {
		return paths
	}
	return append(paths, path)
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

	if req.DockerEnabled {
		files = append(files, dockerDaemonConfigFile(req))
		if dockerClientProxyConfigured(req) {
			files = append(files, dockerClientConfigFile(req))
		}
	}

	return files
}

func usesGatewayDNS(mode string) bool {
	mode = strings.TrimSpace(mode)
	return strings.EqualFold(mode, "monitor") || strings.EqualFold(mode, "enforce")
}

func dockerDaemonConfigFile(req PlanRequest) GeneratedFile {
	socketPath := strings.TrimSpace(req.DockerSocketPath)
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	config := map[string]any{
		"bridge":         "none",
		"features":       map[string]bool{"containerd-snapshotter": false},
		"hosts":          []string{"unix://" + socketPath},
		"ip-forward":     false,
		"ip6tables":      false,
		"ip-masq":        false,
		"iptables":       false,
		"storage-driver": "vfs",
		"proxies": map[string]string{
			"http-proxy":  strings.TrimSpace(req.DockerHTTPProxy),
			"https-proxy": strings.TrimSpace(req.DockerHTTPSProxy),
			"no-proxy":    strings.TrimSpace(req.DockerNoProxy),
		},
	}
	if dataRoot := strings.TrimSpace(req.DockerDataRoot); dataRoot != "" {
		config["data-root"] = dataRoot
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshal docker daemon config: %v", err))
	}
	content = append(content, '\n')
	return GeneratedFile{
		Path:    "/etc/docker/daemon.json",
		Content: string(content),
		Mode:    0o644,
	}
}

func dockerClientProxyConfigured(req PlanRequest) bool {
	return strings.TrimSpace(req.DockerHTTPProxy) != "" ||
		strings.TrimSpace(req.DockerHTTPSProxy) != "" ||
		strings.TrimSpace(req.DockerNoProxy) != ""
}

func dockerClientConfigFile(req PlanRequest) GeneratedFile {
	config := map[string]any{
		"proxies": map[string]any{
			"default": map[string]string{
				"httpProxy":  strings.TrimSpace(req.DockerHTTPProxy),
				"httpsProxy": strings.TrimSpace(req.DockerHTTPSProxy),
				"noProxy":    strings.TrimSpace(req.DockerNoProxy),
			},
		},
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshal docker client config: %v", err))
	}
	content = append(content, '\n')
	return GeneratedFile{
		Path:    "/etc/docker/config.json",
		Content: string(content),
		Mode:    0o644,
	}
}
