package config

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Sandbox  SandboxConfig  `yaml:"sandbox"`
	Network  NetworkConfig  `yaml:"network"`
	Policy   PolicyConfig   `yaml:"policy"`
	Mounts   MountsConfig   `yaml:"mounts"`
	BuildKit BuildKitConfig `yaml:"buildkit"`
	Docker   DockerConfig   `yaml:"docker"`
	GVisor   GVisorConfig   `yaml:"gvisor"`
}

type SandboxConfig struct {
	Rootfs         string   `yaml:"rootfs"`
	RootfsSource   string   `yaml:"rootfs_source"`
	Hostname       string   `yaml:"hostname"`
	Workdir        string   `yaml:"workdir"`
	WorkdirOverlay *bool    `yaml:"workdir_overlay"`
	InheritEnv     bool     `yaml:"inherit_env"`
	Env            []string `yaml:"env"`
	CommandShell   string   `yaml:"command_shell"`
}

type NetworkConfig struct {
	Mode             string                 `yaml:"mode"`
	Subnet           string                 `yaml:"subnet"`
	DNS              DNSConfig              `yaml:"dns"`
	TransparentProxy TransparentProxyConfig `yaml:"transparent_proxy"`
}

type DNSConfig struct {
	BindAddr string   `yaml:"bind_addr"`
	Upstream []string `yaml:"upstream"`
}

type TransparentProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Mode     string `yaml:"mode"`
	HTTPPort int    `yaml:"http_port"`
	TLSPort  int    `yaml:"tls_port"`
}

type PolicyConfig struct {
	AllowDomains      []string     `yaml:"allow_domains"`
	DenyDomains       []string     `yaml:"deny_domains"`
	ExtraAllowedCIDRs []string     `yaml:"extra_allowed_cidrs"`
	Egress            []EgressRule `yaml:"egress"`
}

type EgressRule struct {
	Hostname  string          `yaml:"hostname"`
	CIDR      string          `yaml:"cidr"`
	Transport []TransportRule `yaml:"transport"`
	ICMP      []ICMPRule      `yaml:"icmp"`
}

type TransportRule struct {
	Protocol string `yaml:"protocol"`
	Ports    []int  `yaml:"ports"`
}

type ICMPRule struct {
	Type int `yaml:"type"`
	Code int `yaml:"code"`
}

type MountsConfig struct {
	ExtraRO []string `yaml:"extra_ro"`
	ExtraRW []string `yaml:"extra_rw"`
}

type BuildKitConfig struct {
	Enabled    bool   `yaml:"enabled"`
	HelperPath string `yaml:"helper_path"`
	StateDir   string `yaml:"state_dir"`
	RunDir     string `yaml:"run_dir"`
	Daemonless *bool  `yaml:"daemonless"`
}

type DockerConfig struct {
	Mode                        string        `yaml:"mode"`
	User                        string        `yaml:"user"`
	UID                         int           `yaml:"uid"`
	GID                         int           `yaml:"gid"`
	HomeDir                     string        `yaml:"home_dir"`
	RuntimeDir                  string        `yaml:"runtime_dir"`
	Enabled                     bool          `yaml:"enabled"`
	DataRoot                    string        `yaml:"data_root"`
	SocketPath                  string        `yaml:"socket_path"`
	WaitForSocket               bool          `yaml:"wait_for_socket"`
	ReadyTimeout                time.Duration `yaml:"ready_timeout"`
	HostNetworkNestedContainers bool          `yaml:"host_network_nested_containers"`
}

type GVisorConfig struct {
	Platform string `yaml:"platform"`
	Network  string `yaml:"network"`
	Debug    bool   `yaml:"debug"`
}

func (cfg BuildKitConfig) HelperPathValue() string {
	helperPath := strings.TrimSpace(cfg.HelperPath)
	if helperPath == "" {
		return "/box/bin/buildctl-daemonless.sh"
	}
	return helperPath
}

func (cfg BuildKitConfig) StateDirValue() string {
	stateDir := strings.TrimSpace(cfg.StateDir)
	if stateDir == "" {
		return "/var/cache/buildkit"
	}
	return stateDir
}

func (cfg BuildKitConfig) RunDirValue() string {
	runDir := strings.TrimSpace(cfg.RunDir)
	if runDir == "" {
		return "/run/buildkit"
	}
	return runDir
}

func (cfg BuildKitConfig) DaemonlessValue() bool {
	if cfg.Daemonless == nil {
		return true
	}
	return *cfg.Daemonless
}

func (cfg SandboxConfig) WorkdirOverlayEnabled() bool {
	if cfg.WorkdirOverlay == nil {
		return true
	}
	return *cfg.WorkdirOverlay
}

func (cfg DockerConfig) ModeValue() string {
	mode := strings.TrimSpace(cfg.Mode)
	if mode == "" {
		return "rootless"
	}
	return mode
}

func (cfg DockerConfig) UserValue() string {
	user := strings.TrimSpace(cfg.User)
	if user == "" {
		return "box"
	}
	return user
}

func (cfg DockerConfig) UIDValue() int {
	if cfg.UID <= 0 {
		return 1000
	}
	return cfg.UID
}

func (cfg DockerConfig) GIDValue() int {
	if cfg.GID <= 0 {
		return 1000
	}
	return cfg.GID
}

func (cfg DockerConfig) HomeDirValue() string {
	home := strings.TrimSpace(cfg.HomeDir)
	if home == "" {
		return filepath.Join("/home", cfg.UserValue())
	}
	return home
}

func (cfg DockerConfig) RuntimeDirValue() string {
	runtimeDir := strings.TrimSpace(cfg.RuntimeDir)
	if runtimeDir == "" {
		return filepath.Join("/run/user", strconv.Itoa(cfg.UIDValue()))
	}
	return runtimeDir
}

func (cfg DockerConfig) DataRootValue() string {
	dataRoot := strings.TrimSpace(cfg.DataRoot)
	if dataRoot == "" {
		return filepath.Join(cfg.HomeDirValue(), ".local/share/docker")
	}
	return dataRoot
}

func (cfg DockerConfig) SocketPathValue() string {
	socketPath := strings.TrimSpace(cfg.SocketPath)
	if socketPath == "" {
		return filepath.Join(cfg.RuntimeDirValue(), "docker.sock")
	}
	return socketPath
}
