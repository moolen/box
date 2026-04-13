package config

type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
	Mounts  MountsConfig  `yaml:"mounts"`
	GVisor  GVisorConfig  `yaml:"gvisor"`
}

type SandboxConfig struct {
	Rootfs         string   `yaml:"rootfs"`
	Hostname       string   `yaml:"hostname"`
	Workdir        string   `yaml:"workdir"`
	WorkdirOverlay bool     `yaml:"workdir_overlay"`
	InheritEnv     bool     `yaml:"inherit_env"`
	Env            []string `yaml:"env"`
	CommandShell   string   `yaml:"command_shell"`
}

type NetworkConfig struct {
	Mode   string              `yaml:"mode"`
	Subnet string              `yaml:"subnet"`
	DNS    DNSConfig           `yaml:"dns"`
	Policy []NetworkPolicyRule `yaml:"policy"`
}

type DNSConfig struct {
	Upstream []string `yaml:"upstream"`
}

type NetworkPolicyRule struct {
	Hostname string            `yaml:"hostname"`
	CIDR     string            `yaml:"cidr"`
	Ports    []int             `yaml:"ports"`
	HTTP     *HTTPPolicyConfig `yaml:"http"`
	ICMP     []ICMPPolicyRule  `yaml:"icmp"`
}

type HTTPPolicyConfig struct {
	Path []string `yaml:"path"`
}

type ICMPPolicyRule struct {
	Type int  `yaml:"type"`
	Code *int `yaml:"code"`
}

type MountsConfig struct {
	ExtraRO  []string          `yaml:"extra_ro"`
	ExtraRW  []string          `yaml:"extra_rw"`
	StagedRO []StagedFileMount `yaml:"staged_ro"`
	StagedRW []StagedFileMount `yaml:"staged_rw"`
}

type StagedFileMount struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	Mode     *int   `yaml:"mode"`
	Optional bool   `yaml:"optional"`
}

type GVisorConfig struct {
	Platform string `yaml:"platform"`
}
