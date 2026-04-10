package firewall

import (
	"errors"
	"fmt"
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
	tproxyRule := fmt.Sprintf(
		"iifname %s ip saddr %s tcp dport {80,443} tproxy ip to :%d meta mark set %d",
		in.HostVeth,
		in.SubnetCIDR,
		in.ProxyPort,
		in.FWMark,
	)

	return MonitorPlan{
		Rules: []string{
			dnsRule,
			tproxyRule,
		},
		Commands: []string{
			fmt.Sprintf("nft add table inet %s", in.TableName),
			fmt.Sprintf("nft add chain inet %s prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }", in.TableName),
			fmt.Sprintf("nft add chain inet %s prerouting_tproxy { type filter hook prerouting priority mangle; policy accept; }", in.TableName),
			fmt.Sprintf("nft add rule inet %s prerouting_dns %s", in.TableName, dnsRule),
			fmt.Sprintf("nft add rule inet %s prerouting_tproxy %s", in.TableName, tproxyRule),
		},
	}, nil
}
