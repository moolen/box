package config

type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
	// Legacy shim for callers still referencing cfg.Policy. This is intentionally
	// not loadable from YAML; policy now lives under network.policy.
	Policy PolicyConfig `yaml:"-"`
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
	// Legacy shim for callers still referencing cfg.Network.TransparentProxy.
	// Intentionally not loadable from YAML; it mirrors network.envoy after Load().
	TransparentProxy TransparentProxyConfig `yaml:"-"`
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

// Legacy shim type for older packages. Do not accept this from YAML.
type TransparentProxyConfig struct {
	Enabled  bool   `yaml:"-"`
	Mode     string `yaml:"-"`
	HTTPPort int    `yaml:"-"`
	TLSPort  int    `yaml:"-"`
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

// Legacy shim types for older packages. Do not accept these from YAML.
type PolicyConfig struct {
	AllowDomains      []string     `yaml:"-"`
	DenyDomains       []string     `yaml:"-"`
	ExtraAllowedCIDRs []string     `yaml:"-"`
	Egress            []EgressRule `yaml:"-"`
}

type EgressRule struct {
	Hostname  string          `yaml:"-"`
	CIDR      string          `yaml:"-"`
	Transport []TransportRule `yaml:"-"`
	ICMP      []ICMPRule      `yaml:"-"`
}

type TransportRule struct {
	Protocol string `yaml:"-"`
	Ports    []int  `yaml:"-"`
}

type ICMPRule struct {
	Type int `yaml:"-"`
	Code int `yaml:"-"`
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
