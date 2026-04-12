package config

type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
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
	Mode   string              `yaml:"mode"`
	Subnet string              `yaml:"subnet"`
	DNS    DNSConfig           `yaml:"dns"`
	Envoy  EnvoyConfig         `yaml:"envoy"`
	Policy []NetworkPolicyRule `yaml:"policy"`
}

type DNSConfig struct {
	BindAddr string   `yaml:"bind_addr"`
	Upstream []string `yaml:"upstream"`
}

type EnvoyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Mode     string `yaml:"mode"`
	HTTPPort int    `yaml:"http_port"`
	TLSPort  int    `yaml:"tls_port"`
}

type NetworkPolicyRule struct {
	Hostname string            `yaml:"hostname"`
	CIDR     string            `yaml:"cidr"`
	Ports    []int             `yaml:"ports"`
	HTTP     *HTTPPolicyConfig `yaml:"http"`
}

type HTTPPolicyConfig struct {
	Path []string `yaml:"path"`
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
