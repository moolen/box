package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type MonitorPlanInput struct {
	TableName  string
	HostVeth   string
	SubnetCIDR string
	DNSPort    int
	ProxyPort  int
	FWMark     uint32
}

type MonitorPlan struct {
	Rules    []string
	Commands []string
}

type EnforcePlanInput struct {
	TableName  string
	HostVeth   string
	SubnetCIDR string
	DNSPort    int
	ProxyPort  int
	Rules      []EnforceRule
}

type EnforcePlan struct {
	Commands []string
}

type EnforceRule struct {
	SetName   string
	CIDRs     []string
	Transport []TransportMatch
	ICMP      []ICMPMatch
}

type TransportMatch struct {
	Protocol string
	Ports    []int
}

type ICMPMatch struct {
	Type int
	Code int
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
		"iifname %s ip saddr %s udp dport 53 redirect to :%d",
		in.HostVeth,
		in.SubnetCIDR,
		in.DNSPort,
	)
	httpRedirectRule := fmt.Sprintf(
		"iifname %s ip saddr %s tcp dport 80 redirect to :%d",
		in.HostVeth,
		in.SubnetCIDR,
		in.ProxyPort,
	)

	return MonitorPlan{
		Rules: []string{
			dnsRule,
			httpRedirectRule,
		},
		Commands: []string{
			fmt.Sprintf("nft add table inet %s", in.TableName),
			fmt.Sprintf("nft add chain inet %s prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
			fmt.Sprintf("nft add chain inet %s prerouting_http { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
			fmt.Sprintf("nft add rule inet %s prerouting_dns %s", in.TableName, dnsRule),
			fmt.Sprintf("nft add rule inet %s prerouting_http %s", in.TableName, httpRedirectRule),
		},
	}, nil
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
		fmt.Sprintf("nft add chain inet %s prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s forward { type filter hook forward priority filter; policy drop; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s input { type filter hook input priority filter; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add rule inet %s prerouting_dns iifname %s ip saddr %s udp dport 53 redirect to :%d", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s prerouting_dns iifname %s ip saddr %s tcp dport 53 redirect to :%d", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s forward ct state established,related accept", in.TableName),
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s udp dport %d accept", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s tcp dport %d accept", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s postrouting ip saddr %s masquerade", in.TableName, in.SubnetCIDR),
	}
	if in.ProxyPort > 0 {
		commands = append(commands,
			fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s tcp dport %d accept", in.TableName, in.HostVeth, in.SubnetCIDR, in.ProxyPort),
		)
	}

	for _, rule := range in.Rules {
		setName := strings.TrimSpace(rule.SetName)
		if setName == "" {
			return EnforcePlan{}, errors.New("rule set name is required")
		}

		commands = append(commands,
			fmt.Sprintf("nft add set inet %s %s { type ipv4_addr; flags interval; }", in.TableName, setName),
		)

		validCIDRs := make([]string, 0, len(rule.CIDRs))
		for _, raw := range rule.CIDRs {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return EnforcePlan{}, fmt.Errorf("parse cidr %q for set %q: %w", raw, setName, err)
			}
			if !prefix.Addr().Is4() {
				return EnforcePlan{}, fmt.Errorf("cidr %q for set %q must be ipv4", raw, setName)
			}
			validCIDRs = append(validCIDRs, prefix.String())
		}
		if len(validCIDRs) > 0 {
			commands = append(commands, fmt.Sprintf("nft add element inet %s %s { %s }", in.TableName, setName, strings.Join(validCIDRs, ", ")))
		}

		for _, match := range rule.Transport {
			protocol := strings.ToLower(strings.TrimSpace(match.Protocol))
			if protocol == "" {
				return EnforcePlan{}, fmt.Errorf("transport protocol is required for set %q", setName)
			}
			if protocol != "tcp" && protocol != "udp" {
				return EnforcePlan{}, fmt.Errorf("transport protocol %q for set %q must be tcp or udp", protocol, setName)
			}
			if len(match.Ports) == 0 {
				return EnforcePlan{}, fmt.Errorf("transport ports are required for set %q", setName)
			}
			for _, port := range match.Ports {
				if port <= 0 || port > 65535 {
					return EnforcePlan{}, fmt.Errorf("transport port %d for set %q must be 1-65535", port, setName)
				}
			}

			commands = append(commands,
				fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s ip daddr @%s %s dport %s accept",
					in.TableName,
					in.HostVeth,
					in.SubnetCIDR,
					setName,
					protocol,
					renderPorts(match.Ports),
				),
				fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s ip daddr @%s %s dport %s accept",
					in.TableName,
					in.HostVeth,
					in.SubnetCIDR,
					setName,
					protocol,
					renderPorts(match.Ports),
				),
			)
		}

		for _, tuple := range rule.ICMP {
			if tuple.Type < 0 || tuple.Type > 255 {
				return EnforcePlan{}, fmt.Errorf("icmp type %d for set %q must be 0-255", tuple.Type, setName)
			}
			if tuple.Code < 0 || tuple.Code > 255 {
				return EnforcePlan{}, fmt.Errorf("icmp code %d for set %q must be 0-255", tuple.Code, setName)
			}
			commands = append(commands,
				fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s ip daddr @%s icmp type %d icmp code %d accept",
					in.TableName,
					in.HostVeth,
					in.SubnetCIDR,
					setName,
					tuple.Type,
					tuple.Code,
				),
				fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s ip daddr @%s icmp type %d icmp code %d accept",
					in.TableName,
					in.HostVeth,
					in.SubnetCIDR,
					setName,
					tuple.Type,
					tuple.Code,
				),
			)
		}
	}

	commands = append(commands,
		fmt.Sprintf("nft add rule inet %s input iifname %s ip saddr %s drop", in.TableName, in.HostVeth, in.SubnetCIDR),
	)

	return EnforcePlan{Commands: commands}, nil
}

func BuildEnforceAllowIPCommand(tableName, setName, rawIP string) (string, error) {
	if strings.TrimSpace(tableName) == "" {
		return "", errors.New("table name is required")
	}
	if strings.TrimSpace(setName) == "" {
		return "", errors.New("set name is required")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return "", fmt.Errorf("parse ip %q: %w", rawIP, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("ip %q must be ipv4", rawIP)
	}
	return fmt.Sprintf("nft add element inet %s %s { %s }", tableName, setName, addr.Unmap().String()), nil
}

func renderPorts(ports []int) string {
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return fmt.Sprintf("{ %s }", strings.Join(values, ", "))
}
