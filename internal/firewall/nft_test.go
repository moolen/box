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

func TestEnforceModeRendersPerRuleSetsAndProtocolAwareAcceptRules(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
				ICMP: []ICMPMatch{{
					Type: 8,
					Code: 0,
				}},
			},
			{
				SetName: "egress_1_v4",
				CIDRs:   []string{"93.184.216.0/24"},
				Transport: []TransportMatch{{
					Protocol: "udp",
					Ports:    []int{443},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add set inet box_deadbeef egress_0_v4 { type ipv4_addr; flags interval; }")
	mustContainCommand(t, plan.Commands, "nft add set inet box_deadbeef egress_1_v4 { type ipv4_addr; flags interval; }")
	mustContainCommandFragments(t, plan.Commands,
		"nft add rule inet box_deadbeef forward",
		"iifname vethhdeadbeef",
		"ip saddr 100.96.0.0/30",
		"ip daddr @egress_0_v4",
		"tcp",
		"dport",
		"443",
		"accept",
	)
	mustContainCommandFragments(t, plan.Commands,
		"nft add rule inet box_deadbeef forward",
		"iifname vethhdeadbeef",
		"ip saddr 100.96.0.0/30",
		"ip daddr @egress_0_v4",
		"icmp",
		"type 8",
		"code 0",
		"accept",
	)
	mustContainCommandFragments(t, plan.Commands,
		"nft add rule inet box_deadbeef forward",
		"iifname vethhdeadbeef",
		"ip saddr 100.96.0.0/30",
		"ip daddr @egress_1_v4",
		"udp",
		"dport",
		"443",
		"accept",
	)
}

func TestEnforceModeDoesNotRenderLegacySharedAllowSet(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	for _, cmd := range plan.Commands {
		if strings.Contains(cmd, "allow_v4") {
			t.Fatalf("legacy allow_v4 reference must not be rendered: %q", cmd)
		}
	}
}

func TestEnforceModeRendersMultiPortTransportMatch(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{80, 443},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	mustContainCommandFragments(t, plan.Commands,
		"nft add rule inet box_deadbeef forward",
		"ip daddr @egress_0_v4",
		"tcp dport { 80, 443 }",
		"accept",
	)
}

func TestEnforceModeNormalizesProtocolCase(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{
					{
						Protocol: "TCP",
						Ports:    []int{443},
					},
					{
						Protocol: "UdP",
						Ports:    []int{53},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	mustContainCommandFragments(t, plan.Commands,
		"ip daddr @egress_0_v4",
		"tcp dport 443",
		"accept",
	)
	mustContainCommandFragments(t, plan.Commands,
		"ip daddr @egress_0_v4",
		"udp dport 53",
		"accept",
	)
}

func TestEnforceModePrepopulatesCIDRRuleSetsOnly(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
			},
			{
				SetName: "egress_1_v4",
				CIDRs:   []string{"93.184.216.0/24"},
				Transport: []TransportMatch{{
					Protocol: "udp",
					Ports:    []int{53},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add set inet box_deadbeef egress_0_v4 { type ipv4_addr; flags interval; }")
	mustContainCommand(t, plan.Commands, "nft add set inet box_deadbeef egress_1_v4 { type ipv4_addr; flags interval; }")
	mustContainCommand(t, plan.Commands, "nft add element inet box_deadbeef egress_1_v4 { 93.184.216.0/24 }")

	if containsFragment(plan.Commands, "nft add element inet box_deadbeef egress_0_v4") {
		t.Fatalf("hostname-backed set must not be pre-populated.\ncommands=%#v", plan.Commands)
	}
}

func TestBuildEnforcePlanRejectsInvalidRuleInputs(t *testing.T) {
	tests := []struct {
		name        string
		rules       []EnforceRule
		wantErrFrag string
	}{
		{
			name: "invalid protocol",
			rules: []EnforceRule{{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "sctp",
					Ports:    []int{443},
				}},
			}},
			wantErrFrag: "protocol",
		},
		{
			name: "missing set name",
			rules: []EnforceRule{{
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
			}},
			wantErrFrag: "rule set name is required",
		},
		{
			name: "invalid icmp tuple",
			rules: []EnforceRule{{
				SetName: "egress_0_v4",
				ICMP: []ICMPMatch{{
					Type: 8,
					Code: 300,
				}},
			}},
			wantErrFrag: "icmp code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildEnforcePlan(EnforcePlanInput{
				TableName:  "box_deadbeef",
				HostVeth:   "vethhdeadbeef",
				SubnetCIDR: "100.96.0.0/30",
				DNSPort:    1053,
				Rules:      tt.rules,
			})
			if err == nil {
				t.Fatalf("BuildEnforcePlan() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrFrag) {
				t.Fatalf("BuildEnforcePlan() error = %q, want contains %q", err.Error(), tt.wantErrFrag)
			}
		})
	}
}

func TestBuildEnforceAllowIPCommandTargetsSpecificRuleSet(t *testing.T) {
	got, err := BuildEnforceAllowIPCommand("box_deadbeef", "egress_0_v4", "93.184.216.34")
	if err != nil {
		t.Fatalf("BuildEnforceAllowIPCommand() error = %v", err)
	}

	want := "nft add element inet box_deadbeef egress_0_v4 { 93.184.216.34 }"
	if got != want {
		t.Fatalf("BuildEnforceAllowIPCommand() = %q, want %q", got, want)
	}
}

func mustContainCommand(t *testing.T, commands []string, want string) {
	t.Helper()
	if !slices.Contains(commands, want) {
		t.Fatalf("command missing.\nwant: %q\ncommands=%#v", want, commands)
	}
}

func mustContainCommandFragments(t *testing.T, commands []string, fragments ...string) {
	t.Helper()
	for _, cmd := range commands {
		matches := true
		for _, fragment := range fragments {
			if !strings.Contains(cmd, fragment) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("command missing with fragments=%#v\ncommands=%#v", fragments, commands)
}

func containsFragment(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}
