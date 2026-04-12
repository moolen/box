package config

type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
	Policy  PolicyConfig  `yaml:"policy"`
	Mounts  MountsConfig  `yaml:"mounts"`
	GVisor  GVisorConfig  `yaml:"gvisor"`
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

type GVisorConfig struct {
	Platform string `yaml:"platform"`
	Network  string `yaml:"network"`
	Debug    bool   `yaml:"debug"`
}

func (cfg SandboxConfig) WorkdirOverlayEnabled() bool {
	if cfg.WorkdirOverlay == nil {
		return true
	}
	return *cfg.WorkdirOverlay
}
