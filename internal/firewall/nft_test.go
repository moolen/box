package firewall

import (
	"slices"
	"strings"
	"testing"
)

func TestEnforceModeRedirectsTCPAndDNSAndBlocksOtherUDP(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:       "box_deadbeef",
		HostVeth:        "vethhdeadbeef",
		SubnetCIDR:      "100.96.0.0/30",
		GatewayIP:       "100.96.0.1",
		DNSPort:         15353,
		ExplicitPort:    18080,
		TransparentPort: 19001,
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error: %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 ip daddr 100.96.0.1 meta l4proto tcp tcp dport 18080 return")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto tcp redirect to :19001")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto udp udp dport 53 redirect to :15353")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto udp drop")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto icmp accept")
}

func TestMonitorModeRedirectsTCPAndDNSAndBlocksOtherUDP(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:    "box_deadbeef",
		HostVeth:     "vethhdeadbeef",
		SubnetCIDR:   "100.96.0.0/30",
		DNSPort:      53,
		GatewayIP:    "100.96.0.1",
		ExplicitPort: 18080,
		ProxyPort:    19001,
		FWMark:       0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add chain inet box_deadbeef prerouting_envoy")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 ip daddr 100.96.0.1 meta l4proto tcp tcp dport 18080 return")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto tcp redirect to :19001")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef prerouting_envoy iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto udp udp dport 53 redirect to :53")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward ct state established,related accept")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto udp drop")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 meta l4proto icmp accept")
}

func TestIIFNameTokenIsNotQuoted(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    53,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	for _, rule := range plan.Rules {
		if strings.Contains(rule, `iifname "vethhdeadbeef"`) {
			t.Fatalf("iifname token must not be quoted: %q", rule)
		}
	}
}

func TestPolicyRoutingPlanUsesLocalRouteToLoopback(t *testing.T) {
	cmds, err := BuildPolicyRoutingPlan(0x101, 10001)
	if err != nil {
		t.Fatalf("BuildPolicyRoutingPlan() error: %v", err)
	}

	wantRule := "ip rule add fwmark 257 lookup 10001"
	wantRoute := "ip route add local 0.0.0.0/0 dev lo table 10001"
	if !slices.Contains(cmds, wantRule) {
		t.Fatalf("policy rule missing.\nwant: %q\ngot: %#v", wantRule, cmds)
	}
	if !slices.Contains(cmds, wantRoute) {
		t.Fatalf("local route missing.\nwant: %q\ngot: %#v", wantRoute, cmds)
	}
}

func TestBuildMonitorPlanRejectsZeroFWMark(t *testing.T) {
	_, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    53,
		ProxyPort:  18080,
		FWMark:     0,
	})
	if err == nil {
		t.Fatalf("BuildMonitorPlan() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "fwmark must be non-zero") {
		t.Fatalf("BuildMonitorPlan() error = %q, want contains %q", err.Error(), "fwmark must be non-zero")
	}
}

func TestEnforceModeRendersEnvoyRedirectAndDropsNonDNSUDP(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:       "box_deadbeef",
		HostVeth:        "vethhdeadbeef",
		SubnetCIDR:      "100.96.0.0/30",
		DNSPort:         1053,
		TransparentPort: 19001,
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error: %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add chain inet box_deadbeef prerouting_envoy")
	mustContainCommand(t, plan.Commands, "udp dport 53 redirect to :1053")
	mustContainCommand(t, plan.Commands, "tcp redirect to :19001")
	mustContainCommand(t, plan.Commands, "meta l4proto udp drop")
	mustContainCommand(t, plan.Commands, "meta l4proto icmp accept")
	mustContainCommand(t, plan.Commands, "masquerade")
	for _, cmd := range plan.Commands {
		if strings.Contains(cmd, "allow_v4") {
			t.Fatalf("allowset model must not be rendered (found %q)\ncommands=%#v", cmd, plan.Commands)
		}
	}
}

func containsFragment(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func mustContainCommand(t *testing.T, commands []string, fragment string) {
	t.Helper()
	for _, cmd := range commands {
		if strings.Contains(cmd, fragment) {
			return
		}
	}
	t.Fatalf("missing command containing %q\ncommands=%#v", fragment, commands)
}
