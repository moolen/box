package config

import "time"

type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
	Policy  PolicyConfig  `yaml:"policy"`
	Mounts  MountsConfig  `yaml:"mounts"`
	Docker  DockerConfig  `yaml:"docker"`
	GVisor  GVisorConfig  `yaml:"gvisor"`
}

type SandboxConfig struct {
	Rootfs       string   `yaml:"rootfs"`
	RootfsSource string   `yaml:"rootfs_source"`
	Hostname     string   `yaml:"hostname"`
	Workdir      string   `yaml:"workdir"`
	Env          []string `yaml:"env"`
	CommandShell string   `yaml:"command_shell"`
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
	AllowDomains      []string `yaml:"allow_domains"`
	DenyDomains       []string `yaml:"deny_domains"`
	AllowCIDRs        []string `yaml:"allow_cidrs"`
	DenyCIDRs         []string `yaml:"deny_cidrs"`
	ExtraAllowedCIDRs []string `yaml:"extra_allowed_cidrs"`
	LogAllConnects    bool     `yaml:"log_all_connects"`
}

type MountsConfig struct {
	ExtraRO []string `yaml:"extra_ro"`
	ExtraRW []string `yaml:"extra_rw"`
}

type DockerConfig struct {
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
