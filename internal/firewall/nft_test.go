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
		DNSPort:    53,
		ProxyPort:  18080,
		FWMark:     0x101,
	})
	if err != nil {
		t.Fatalf("BuildMonitorPlan() error: %v", err)
	}

	want := "iifname vethhdeadbeef ip saddr 100.96.0.0/30 udp dport 53 redirect to :53"
	if !slices.Contains(plan.Rules, want) {
		t.Fatalf("DNS rule missing.\nwant: %q\ngot: %#v", want, plan.Rules)
	}

	wantAttach := "nft add rule inet box_deadbeef prerouting_dns iifname vethhdeadbeef ip saddr 100.96.0.0/30 udp dport 53 redirect to :53"
	if !slices.Contains(plan.Commands, wantAttach) {
		t.Fatalf("DNS rule must be attached to DNS prerouting chain.\nwant: %q\ngot: %#v", wantAttach, plan.Commands)
	}
}

func TestMonitorModeRendersScopedHTTPRedirectRule(t *testing.T) {
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

	want := "tcp dport 80 redirect to :18080"
	if !containsFragment(plan.Rules, want) {
		t.Fatalf("HTTP redirect rule fragment missing.\nwant fragment: %q\ngot: %#v", want, plan.Rules)
	}

	wantAttachFragment := "nft add rule inet box_deadbeef prerouting_http "
	if !containsFragment(plan.Commands, wantAttachFragment) {
		t.Fatalf("HTTP redirect rule must be attached to HTTP prerouting chain.\nwant fragment: %q\ngot: %#v", wantAttachFragment, plan.Commands)
	}
}

func TestMonitorModeRendersFullyScopedHTTPRedirectRule(t *testing.T) {
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

	var httpRule string
	for _, rule := range plan.Rules {
		if strings.Contains(rule, "tcp dport 80 redirect to :18080") {
			httpRule = rule
			break
		}
	}
	if httpRule == "" {
		t.Fatalf("HTTP redirect rule missing from rules: %#v", plan.Rules)
	}
	if !strings.Contains(httpRule, "iifname vethhdeadbeef") {
		t.Fatalf("HTTP redirect rule must scope by host veth. got: %q", httpRule)
	}
	if !strings.Contains(httpRule, "ip saddr 100.96.0.0/30") {
		t.Fatalf("HTTP redirect rule must scope by subnet CIDR. got: %q", httpRule)
	}
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

func TestMonitorModeRendersSeparateDNSAndHTTPChains(t *testing.T) {
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

	wantDNSChain := "nft add chain inet box_deadbeef prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }"
	wantHTTPChain := "nft add chain inet box_deadbeef prerouting_http { type nat hook prerouting priority dstnat; policy accept; }"
	if !slices.Contains(plan.Commands, wantDNSChain) {
		t.Fatalf("DNS chain command missing.\nwant: %q\ngot: %#v", wantDNSChain, plan.Commands)
	}
	if !slices.Contains(plan.Commands, wantHTTPChain) {
		t.Fatalf("HTTP chain command missing.\nwant: %q\ngot: %#v", wantHTTPChain, plan.Commands)
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

func TestEnforceModeRendersDNSRedirectForwardAllowsetAndMasquerade(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:         "box_deadbeef",
		HostVeth:          "vethhdeadbeef",
		SubnetCIDR:        "100.96.0.0/30",
		DNSPort:           1053,
		ExtraAllowedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error: %v", err)
	}

	wantFragments := []string{
		"nft add set inet box_deadbeef allow_v4 { type ipv4_addr; flags interval; }",
		"nft add chain inet box_deadbeef prerouting_dns { type nat hook prerouting priority dstnat; policy accept; }",
		"nft add chain inet box_deadbeef forward { type filter hook forward priority filter; policy drop; }",
		"nft add chain inet box_deadbeef postrouting { type nat hook postrouting priority srcnat; policy accept; }",
		"nft add rule inet box_deadbeef prerouting_dns iifname vethhdeadbeef ip saddr 100.96.0.0/30 udp dport 53 redirect to :1053",
		"nft add rule inet box_deadbeef prerouting_dns iifname vethhdeadbeef ip saddr 100.96.0.0/30 tcp dport 53 redirect to :1053",
		"nft add rule inet box_deadbeef forward ct state established,related accept",
		"nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 ip daddr @allow_v4 accept",
		"nft add rule inet box_deadbeef postrouting ip saddr 100.96.0.0/30 masquerade",
		"nft add element inet box_deadbeef allow_v4 { 10.0.0.0/8, 192.168.0.0/16 }",
	}
	for _, want := range wantFragments {
		if !slices.Contains(plan.Commands, want) {
			t.Fatalf("BuildEnforcePlan() commands missing %q\ncommands=%#v", want, plan.Commands)
		}
	}
}

func TestEnforceAllowIPCommandUsesRuntimeOwnedAllowset(t *testing.T) {
	got, err := BuildEnforceAllowIPCommand("box_deadbeef", "93.184.216.34")
	if err != nil {
		t.Fatalf("BuildEnforceAllowIPCommand() error = %v", err)
	}

	want := "nft add element inet box_deadbeef allow_v4 { 93.184.216.34 }"
	if got != want {
		t.Fatalf("BuildEnforceAllowIPCommand() = %q, want %q", got, want)
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
