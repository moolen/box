package firewall

import (
	"errors"
	"fmt"
	"strings"
)

type MonitorPlanInput struct {
	TableName    string
	HostVeth     string
	SubnetCIDR   string
	GatewayIP    string
	DNSPort      int
	ExplicitPort int
	ProxyPort    int
	FWMark       uint32
}

type MonitorPlan struct {
	Rules    []string
	Commands []string
}

type EnforcePlanInput struct {
	TableName       string
	HostVeth        string
	SubnetCIDR      string
	GatewayIP       string
	DNSPort         int
	ExplicitPort    int
	TransparentPort int
}

type EnforcePlan struct {
	Commands []string
}

func BuildMonitorPlan(in MonitorPlanInput) (MonitorPlan, error) {
	if strings.TrimSpace(in.TableName) == "" {
		return MonitorPlan{}, errors.New("table name is required")
	}
	if strings.TrimSpace(in.HostVeth) == "" {
		return MonitorPlan{}, errors.New("host veth is required")
	}
	if strings.TrimSpace(in.SubnetCIDR) == "" {
		return MonitorPlan{}, errors.New("subnet cidr is required")
	}
	if in.FWMark == 0 {
		return MonitorPlan{}, errors.New("fwmark must be non-zero")
	}
	if in.DNSPort <= 0 || in.ProxyPort <= 0 {
		return MonitorPlan{}, errors.New("dns and proxy ports must be positive")
	}

	dnsRule := fmt.Sprintf(
		"iifname %s ip saddr %s meta l4proto udp udp dport 53 redirect to :%d",
		in.HostVeth,
		in.SubnetCIDR,
		in.DNSPort,
	)
	tcpRedirectRule := fmt.Sprintf(
		"iifname %s ip saddr %s meta l4proto tcp redirect to :%d",
		in.HostVeth,
		in.SubnetCIDR,
		in.ProxyPort,
	)

	rules := []string{dnsRule}
	if strings.TrimSpace(in.GatewayIP) != "" && in.ExplicitPort > 0 {
		rules = append(rules, fmt.Sprintf(
			"iifname %s ip saddr %s ip daddr %s meta l4proto tcp tcp dport %d return",
			in.HostVeth,
			in.SubnetCIDR,
			in.GatewayIP,
			in.ExplicitPort,
		))
	}
	rules = append(rules, tcpRedirectRule)

	plan := MonitorPlan{
		Rules: rules,
		Commands: []string{
			fmt.Sprintf("nft add table inet %s", in.TableName),
			fmt.Sprintf("nft add chain inet %s prerouting_envoy { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
			fmt.Sprintf("nft add chain inet %s input { type filter hook input priority filter; policy accept; }", in.TableName),
			fmt.Sprintf("nft add chain inet %s forward { type filter hook forward priority filter; policy accept; }", in.TableName),
			fmt.Sprintf("nft add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", in.TableName),
			fmt.Sprintf("nft add rule inet %s forward ct state established,related accept", in.TableName),
			fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s meta l4proto icmp accept", in.TableName, in.HostVeth, in.SubnetCIDR),
			fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s meta l4proto udp drop", in.TableName, in.HostVeth, in.SubnetCIDR),
			fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s drop", in.TableName, in.HostVeth, in.SubnetCIDR),
			fmt.Sprintf("nft add rule inet %s postrouting ip saddr %s masquerade", in.TableName, in.SubnetCIDR),
		},
	}
	plan.Commands = append(plan.Commands, protectedInputRules(in.TableName, in.HostVeth, in.SubnetCIDR, in.ExplicitPort, in.ProxyPort, in.DNSPort)...)
	for _, rule := range rules {
		plan.Commands = append(plan.Commands, fmt.Sprintf("nft add rule inet %s prerouting_envoy %s", in.TableName, rule))
	}
	return plan, nil
}

func BuildEnforcePlan(in EnforcePlanInput) (EnforcePlan, error) {
	if strings.TrimSpace(in.TableName) == "" {
		return EnforcePlan{}, errors.New("table name is required")
	}
	if strings.TrimSpace(in.HostVeth) == "" {
		return EnforcePlan{}, errors.New("host veth is required")
	}
	if strings.TrimSpace(in.SubnetCIDR) == "" {
		return EnforcePlan{}, errors.New("subnet cidr is required")
	}
	if in.DNSPort <= 0 {
		return EnforcePlan{}, errors.New("dns port must be positive")
	}

	commands := []string{
		fmt.Sprintf("nft add table inet %s", in.TableName),
		fmt.Sprintf("nft add chain inet %s prerouting_envoy { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s input { type filter hook input priority filter; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s forward { type filter hook forward priority filter; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add rule inet %s forward ct state established,related accept", in.TableName),
		fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s meta l4proto icmp accept", in.TableName, in.HostVeth, in.SubnetCIDR),
		fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s meta l4proto udp drop", in.TableName, in.HostVeth, in.SubnetCIDR),
		fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s drop", in.TableName, in.HostVeth, in.SubnetCIDR),
		fmt.Sprintf("nft add rule inet %s postrouting ip saddr %s masquerade", in.TableName, in.SubnetCIDR),
	}
	commands = append(commands, protectedInputRules(in.TableName, in.HostVeth, in.SubnetCIDR, in.ExplicitPort, in.TransparentPort, in.DNSPort)...)
	preroutingRules := []string{
		fmt.Sprintf("iifname %s ip saddr %s meta l4proto udp udp dport 53 redirect to :%d", in.HostVeth, in.SubnetCIDR, in.DNSPort),
	}
	if strings.TrimSpace(in.GatewayIP) != "" && in.ExplicitPort > 0 {
		preroutingRules = append(preroutingRules, fmt.Sprintf(
			"iifname %s ip saddr %s ip daddr %s meta l4proto tcp tcp dport %d return",
			in.HostVeth,
			in.SubnetCIDR,
			in.GatewayIP,
			in.ExplicitPort,
		))
	}

	// Temporary compatibility: older callers don't know the Envoy transparent listener port yet.
	// Once callers migrate (Task 4), TransparentPort should always be set and this branch can be removed.
	if in.TransparentPort > 0 {
		preroutingRules = append(preroutingRules,
			fmt.Sprintf("iifname %s ip saddr %s meta l4proto tcp redirect to :%d", in.HostVeth, in.SubnetCIDR, in.TransparentPort),
		)
	}
	for _, rule := range preroutingRules {
		commands = append(commands, fmt.Sprintf("nft add rule inet %s prerouting_envoy %s", in.TableName, rule))
	}

	return EnforcePlan{Commands: commands}, nil
}

func protectedInputRules(tableName, hostVeth, subnetCIDR string, explicitPort, transparentPort, dnsPort int) []string {
	var commands []string
	commands = append(commands, protectedTCPInputRules(tableName, hostVeth, subnetCIDR, explicitPort)...)
	commands = append(commands, protectedTransparentTCPInputRules(tableName, hostVeth, subnetCIDR, transparentPort)...)
	commands = append(commands, protectedUDPInputRules(tableName, hostVeth, subnetCIDR, dnsPort)...)
	return commands
}

func protectedTCPInputRules(tableName, hostVeth, subnetCIDR string, port int) []string {
	if port <= 0 {
		return nil
	}
	return []string{
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s meta l4proto tcp tcp dport %d accept", tableName, hostVeth, subnetCIDR, port),
		fmt.Sprintf("nft add rule inet %s input meta l4proto tcp tcp dport %d drop", tableName, port),
	}
}

func protectedUDPInputRules(tableName, hostVeth, subnetCIDR string, port int) []string {
	if port <= 0 {
		return nil
	}
	return []string{
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s meta l4proto udp udp dport %d accept", tableName, hostVeth, subnetCIDR, port),
		fmt.Sprintf("nft add rule inet %s input meta l4proto udp udp dport %d drop", tableName, port),
	}
}

func protectedTransparentTCPInputRules(tableName, hostVeth, subnetCIDR string, port int) []string {
	if port <= 0 {
		return nil
	}
	return []string{
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s meta l4proto tcp tcp dport %d accept", tableName, hostVeth, subnetCIDR, port),
		fmt.Sprintf("nft add rule inet %s input iifname lo meta l4proto tcp tcp dport %d accept", tableName, port),
		fmt.Sprintf("nft add rule inet %s input meta l4proto tcp tcp dport %d drop", tableName, port),
	}
}
