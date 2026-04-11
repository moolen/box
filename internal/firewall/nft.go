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
	TableName         string
	HostVeth          string
	SubnetCIDR        string
	DNSPort           int
	ExtraAllowedCIDRs []string
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
		fmt.Sprintf("nft add set inet %s allow_v4 { type ipv4_addr; flags interval; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s forward { type filter hook forward priority filter; policy drop; }", in.TableName),
		fmt.Sprintf("nft add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", in.TableName),
		fmt.Sprintf("nft add rule inet %s prerouting_dns iifname %s ip saddr %s udp dport 53 redirect to :%d", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s prerouting_dns iifname %s ip saddr %s tcp dport 53 redirect to :%d", in.TableName, in.HostVeth, in.SubnetCIDR, in.DNSPort),
		fmt.Sprintf("nft add rule inet %s forward ct state established,related accept", in.TableName),
		fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s ip daddr @allow_v4 accept", in.TableName, in.HostVeth, in.SubnetCIDR),
		fmt.Sprintf("nft add rule inet %s postrouting ip saddr %s masquerade", in.TableName, in.SubnetCIDR),
	}

	if len(in.ExtraAllowedCIDRs) > 0 {
		validCIDRs := make([]string, 0, len(in.ExtraAllowedCIDRs))
		for _, raw := range in.ExtraAllowedCIDRs {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(trimmed)
			if err != nil {
				return EnforcePlan{}, fmt.Errorf("parse extra allowed cidr %q: %w", raw, err)
			}
			if !prefix.Addr().Is4() {
				return EnforcePlan{}, fmt.Errorf("extra allowed cidr %q must be ipv4", raw)
			}
			validCIDRs = append(validCIDRs, prefix.String())
		}
		if len(validCIDRs) > 0 {
			commands = append(commands, fmt.Sprintf("nft add element inet %s allow_v4 { %s }", in.TableName, strings.Join(validCIDRs, ", ")))
		}
	}

	return EnforcePlan{Commands: commands}, nil
}

func BuildEnforceAllowIPCommand(tableName, rawIP string) (string, error) {
	if strings.TrimSpace(tableName) == "" {
		return "", errors.New("table name is required")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return "", fmt.Errorf("parse ip %q: %w", rawIP, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("ip %q must be ipv4", rawIP)
	}
	return fmt.Sprintf("nft add element inet %s allow_v4 { %s }", tableName, addr.Unmap().String()), nil
}
