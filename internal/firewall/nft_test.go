package firewall

import (
	"slices"
	"strings"
	"testing"
)

func TestMonitorModeRendersScopedDNSRule(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	want := "iifname vethhdeadbeef ip saddr 100.96.0.0/30 udp dport 53 redirect to :1053"
	if !slices.Contains(plan.Rules, want) {
		t.Fatalf("DNS rule missing.\nwant: %q\ngot: %#v", want, plan.Rules)
	}

	wantAttach := "nft add rule inet box_deadbeef prerouting_dns iifname vethhdeadbeef ip saddr 100.96.0.0/30 udp dport 53 redirect to :1053"
	if !slices.Contains(plan.Commands, wantAttach) {
		t.Fatalf("DNS rule must be attached to DNS prerouting chain.\nwant: %q\ngot: %#v", wantAttach, plan.Commands)
	}
}

func TestMonitorModeRendersScopedTPROXYRuleWithIPFamilyToken(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	want := "tproxy ip to :18080"
	if !containsFragment(plan.Rules, want) {
		t.Fatalf("TPROXY rule fragment missing.\nwant fragment: %q\ngot: %#v", want, plan.Rules)
	}

	wantAttachFragment := "nft add rule inet box_deadbeef prerouting_tproxy "
	if !containsFragment(plan.Commands, wantAttachFragment) {
		t.Fatalf("TPROXY rule must be attached to TPROXY prerouting chain.\nwant fragment: %q\ngot: %#v", wantAttachFragment, plan.Commands)
	}
}

func TestMonitorModeRendersFullyScopedTPROXYRule(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	var tproxyRule string
	for _, rule := range plan.Rules {
		if strings.Contains(rule, "tproxy ip to :18080") {
			tproxyRule = rule
			break
		}
	}
	if tproxyRule == "" {
		t.Fatalf("TPROXY rule missing from rules: %#v", plan.Rules)
	}
	if !strings.Contains(tproxyRule, "iifname vethhdeadbeef") {
		t.Fatalf("TPROXY rule must scope by host veth. got: %q", tproxyRule)
	}
	if !strings.Contains(tproxyRule, "ip saddr 100.96.0.0/30") {
		t.Fatalf("TPROXY rule must scope by subnet CIDR. got: %q", tproxyRule)
	}
}

func TestIIFNameTokenIsNotQuoted(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
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

func TestMonitorModeRendersSeparateDNSAndTPROXYChains(t *testing.T) {
	plan, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	wantDNSChain := "nft add chain inet box_deadbeef prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }"
	wantTPROXYChain := "nft add chain inet box_deadbeef prerouting_tproxy { type filter hook prerouting priority mangle; policy accept; }"
	if !slices.Contains(plan.Commands, wantDNSChain) {
		t.Fatalf("DNS chain command missing.\nwant: %q\ngot: %#v", wantDNSChain, plan.Commands)
	}
	if !slices.Contains(plan.Commands, wantTPROXYChain) {
		t.Fatalf("TPROXY chain command missing.\nwant: %q\ngot: %#v", wantTPROXYChain, plan.Commands)
	}
}

func TestBuildMonitorPlanRejectsZeroFWMark(t *testing.T) {
	_, err := BuildMonitorPlan(MonitorPlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
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

func containsFragment(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
