package gvisor

import (
	"fmt"
	"strings"
	"unicode"

	"gvisor-net/internal/config"
	"gvisor-net/internal/rootfs"
)

const defaultPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type Spec struct {
	OCIVersion string      `json:"ociVersion"`
	Process    ProcessSpec `json:"process"`
	Root       RootSpec    `json:"root"`
	Hostname   string      `json:"hostname,omitempty"`
	Mounts     []MountSpec `json:"mounts,omitempty"`
	Linux      LinuxSpec   `json:"linux,omitempty"`
}

type ProcessSpec struct {
	Args         []string               `json:"args"`
	Cwd          string                 `json:"cwd"`
	Env          []string               `json:"env,omitempty"`
	Capabilities *LinuxCapabilitiesSpec `json:"capabilities,omitempty"`
}

type RootSpec struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"readonly,omitempty"`
}

type MountSpec struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type LinuxSpec struct {
	Namespaces []LinuxNamespace `json:"namespaces,omitempty"`
}

type LinuxCapabilitiesSpec struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

type LinuxNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type BuildSpecRequest struct {
	Config               config.Config
	Workdir              string
	Payload              string
	ExtraEnv             []string
	RootfsPlan           rootfs.Plan
	NetworkNamespacePath string
}

func BuildSpec(cfg config.Config, workdir, payload string) (Spec, error) {
	return BuildSandboxSpec(BuildSpecRequest{
		Config:  cfg,
		Workdir: workdir,
		Payload: payload,
	})
}

func BuildSandboxSpec(req BuildSpecRequest) (Spec, error) {
	cfg := req.Config
	shellParts, err := splitShellWords(cfg.Sandbox.CommandShell)
	if err != nil {
		return Spec{}, fmt.Errorf("parse sandbox command shell: %w", err)
	}
	if len(shellParts) == 0 {
		return Spec{}, fmt.Errorf("sandbox command shell is required")
	}

	cwd := strings.TrimSpace(req.Workdir)
	if cwd == "" {
		cwd = strings.TrimSpace(cfg.Sandbox.Workdir)
	}
	if cwd == "" {
		cwd = "/"
	}

	args := make([]string, 0, 2+len(shellParts))
	args = append(args, "/box-initshim")
	args = append(args, shellParts...)
	args = append(args, req.Payload)

	return Spec{
		OCIVersion: "1.0.2",
		Process: ProcessSpec{
			Args:         args,
			Cwd:          cwd,
			Env:          ensureDefaultEnv(cfg.Sandbox.Env, req.ExtraEnv),
			Capabilities: dockerSandboxCapabilities(cfg),
		},
		Root: RootSpec{
			Path:     "rootfs",
			ReadOnly: false,
		},
		Hostname: cfg.Sandbox.Hostname,
		Mounts:   buildMounts(req.RootfsPlan),
		Linux: LinuxSpec{
			Namespaces: buildNamespaces(req.NetworkNamespacePath),
		},
	}, nil
}

func dockerSandboxCapabilities(cfg config.Config) *LinuxCapabilitiesSpec {
	if !cfg.Docker.Enabled {
		return nil
	}

	caps := append([]string(nil), dockerSandboxCapabilitySet...)
	return &LinuxCapabilitiesSpec{
		Bounding:    append([]string(nil), caps...),
		Effective:   append([]string(nil), caps...),
		Inheritable: append([]string(nil), caps...),
		Permitted:   append([]string(nil), caps...),
		Ambient:     append([]string(nil), caps...),
	}
}

var dockerSandboxCapabilitySet = []string{
	"CAP_AUDIT_WRITE",
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_MKNOD",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_SETFCAP",
	"CAP_SETGID",
	"CAP_SETPCAP",
	"CAP_SETUID",
	"CAP_SYS_ADMIN",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
}

func buildMounts(plan rootfs.Plan) []MountSpec {
	mounts := []MountSpec{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
	}
	for _, dir := range plan.WritableDirs {
		mounts = append(mounts, MountSpec{
			Destination: dir,
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     tmpfsOptionsForPath(dir),
		})
	}
	for _, bind := range plan.Binds {
		options := []string{"rbind"}
		if bind.ReadOnly {
			options = append(options, "ro")
		} else {
			options = append(options, "rw")
		}
		mounts = append(mounts, MountSpec{
			Destination: bind.Target,
			Type:        "bind",
			Source:      bind.Source,
			Options:     options,
		})
	}
	return mounts
}

func tmpfsOptionsForPath(path string) []string {
	options := []string{"nosuid", "nodev"}
	switch path {
	case "/tmp", "/var/tmp":
		return append(options, "mode=1777")
	default:
		return append(options, "mode=0755")
	}
}

func buildNamespaces(networkNamespacePath string) []LinuxNamespace {
	namespaces := []LinuxNamespace{
		{Type: "pid"},
		{Type: "ipc"},
		{Type: "uts"},
		{Type: "mount"},
	}
	network := LinuxNamespace{Type: "network"}
	if strings.TrimSpace(networkNamespacePath) != "" {
		network.Path = strings.TrimSpace(networkNamespacePath)
	}
	namespaces = append(namespaces, network)
	return namespaces
}

func ensureDefaultEnv(env []string, forced []string) []string {
	out := mergeEnv(env, forced)
	for _, entry := range out {
		if strings.HasPrefix(entry, "PATH=") {
			return out
		}
	}
	return append(out, defaultPATH)
}

func mergeEnv(base []string, overrides []string) []string {
	out := append([]string(nil), base...)
	indexByKey := make(map[string]int, len(out))
	for i, entry := range out {
		indexByKey[envKey(entry)] = i
	}
	for _, entry := range overrides {
		key := envKey(entry)
		if index, ok := indexByKey[key]; ok {
			out[index] = entry
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, entry)
	}
	return out
}

func envKey(entry string) string {
	if idx := strings.IndexByte(entry, '='); idx >= 0 {
		return entry[:idx]
	}
	return entry
}

func splitShellWords(input string) ([]string, error) {
	var (
		out          []string
		token        []rune
		quote        rune
		escaped      bool
		tokenStarted bool
	)

	flush := func() {
		if !tokenStarted {
			return
		}
		out = append(out, string(token))
		token = token[:0]
		tokenStarted = false
	}

	for _, r := range input {
		if escaped {
			token = append(token, r)
			tokenStarted = true
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			tokenStarted = true
			continue
		}

		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			token = append(token, r)
			tokenStarted = true
			continue
		}

		if unicode.IsSpace(r) {
			flush()
			continue
		}

		if r == '\'' || r == '"' {
			quote = r
			tokenStarted = true
			continue
		}

		token = append(token, r)
		tokenStarted = true
	}

	if escaped {
		return nil, fmt.Errorf("unterminated escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted token")
	}
	flush()

	return out, nil
}
