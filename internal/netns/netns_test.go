package netns

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestAllocateResourcesUsesRuntimeTokenForNames(t *testing.T) {
	first, err := AllocateResources(context.Background(), "runtime-abc-123", "100.96.0.0/29", fakeProbe{})
	if err != nil {
		t.Fatalf("AllocateResources() error: %v", err)
	}
	second, err := AllocateResources(context.Background(), "runtime-abc-123", "100.96.0.0/29", fakeProbe{})
	if err != nil {
		t.Fatalf("AllocateResources() error: %v", err)
	}
	other, err := AllocateResources(context.Background(), "runtime-def-456", "100.96.0.0/29", fakeProbe{})
	if err != nil {
		t.Fatalf("AllocateResources() error: %v", err)
	}

	if first.NetNS != second.NetNS || first.HostVeth != second.HostVeth || first.GuestVeth != second.GuestVeth || first.TableName != second.TableName {
		t.Fatalf("same runtime id must produce stable names: first=%+v second=%+v", first, second)
	}
	if first.NetNS == other.NetNS || first.HostVeth == other.HostVeth || first.GuestVeth == other.GuestVeth || first.TableName == other.TableName {
		t.Fatalf("different runtime ids must not produce identical names: first=%+v other=%+v", first, other)
	}
	if first.NetNS == "" || first.HostVeth == "" || first.GuestVeth == "" || first.TableName == "" {
		t.Fatalf("resource names must be populated: %+v", first)
	}
	if !strings.HasPrefix(first.NetNS, "box-") {
		t.Fatalf("NetNS = %q, want prefix %q", first.NetNS, "box-")
	}
	if !strings.HasPrefix(first.HostVeth, "vethh") {
		t.Fatalf("HostVeth = %q, want prefix %q", first.HostVeth, "vethh")
	}
	if !strings.HasPrefix(first.GuestVeth, "vethg") {
		t.Fatalf("GuestVeth = %q, want prefix %q", first.GuestVeth, "vethg")
	}
	if !strings.HasPrefix(first.TableName, "box_") {
		t.Fatalf("TableName = %q, want prefix %q", first.TableName, "box_")
	}
}

func TestAllocateResourcesSkipsUsedSubnetsRouteTablesAndFWMarks(t *testing.T) {
	probe := fakeProbe{
		subnetsInUse: map[string]bool{
			"100.96.0.0/30": true,
		},
		routeTablesInUse: map[int]bool{
			10000: true,
		},
		fwMarksInUse: map[uint32]bool{
			0x100: true,
		},
	}

	resources, err := AllocateResources(context.Background(), "runtime-abc-123", "100.96.0.0/29", probe)
	if err != nil {
		t.Fatalf("AllocateResources() error: %v", err)
	}

	if resources.SubnetCIDR != "100.96.0.4/30" {
		t.Fatalf("SubnetCIDR = %q, want %q", resources.SubnetCIDR, "100.96.0.4/30")
	}
	if resources.RouteTable == 10000 {
		t.Fatalf("RouteTable = %d, want allocator to skip in-use table", resources.RouteTable)
	}
	if resources.FWMark == 0x100 {
		t.Fatalf("FWMark = %d, want allocator to skip in-use fwmark", resources.FWMark)
	}
}

func TestBuildSetupPlanAssignsGatewayAndSandboxAddress(t *testing.T) {
	resources, err := AllocateResources(context.Background(), "runtime-abc-123", "100.96.0.0/29", fakeProbe{
		subnetsInUse: map[string]bool{
			"100.96.0.0/30": true,
		},
	})
	if err != nil {
		t.Fatalf("AllocateResources() error: %v", err)
	}

	plan, err := BuildSetupPlan(resources)
	if err != nil {
		t.Fatalf("BuildSetupPlan() error: %v", err)
	}

	if plan.GatewayCIDR != "100.96.0.5/30" {
		t.Fatalf("GatewayCIDR = %q, want %q", plan.GatewayCIDR, "100.96.0.5/30")
	}
	if plan.SandboxCIDR != "100.96.0.6/30" {
		t.Fatalf("SandboxCIDR = %q, want %q", plan.SandboxCIDR, "100.96.0.6/30")
	}
	if plan.GatewayIP != "100.96.0.5" {
		t.Fatalf("GatewayIP = %q, want %q", plan.GatewayIP, "100.96.0.5")
	}
	if plan.SandboxIP != "100.96.0.6" {
		t.Fatalf("SandboxIP = %q, want %q", plan.SandboxIP, "100.96.0.6")
	}

	wantCommands := []string{
		fmt.Sprintf("ip netns add %s", resources.NetNS),
		fmt.Sprintf("ip link add %s type veth peer name %s", resources.HostVeth, resources.GuestVeth),
		fmt.Sprintf("ip link set %s netns %s", resources.GuestVeth, resources.NetNS),
		fmt.Sprintf("ip addr add 100.96.0.5/30 dev %s", resources.HostVeth),
		fmt.Sprintf("ip netns exec %s ip addr add 100.96.0.6/30 dev %s", resources.NetNS, resources.GuestVeth),
		fmt.Sprintf("ip netns exec %s ip route add default via 100.96.0.5 dev %s", resources.NetNS, resources.GuestVeth),
	}
	for _, want := range wantCommands {
		if !slices.Contains(plan.Commands, want) {
			t.Fatalf("setup commands missing %q; got %#v", want, plan.Commands)
		}
	}

	wantTeardown := []string{
		fmt.Sprintf("ip link del %s", resources.HostVeth),
		fmt.Sprintf("ip netns del %s", resources.NetNS),
	}
	if !slices.Equal(plan.Teardown, wantTeardown) {
		t.Fatalf("Teardown = %#v, want %#v", plan.Teardown, wantTeardown)
	}
}

type fakeProbe struct {
	subnetsInUse     map[string]bool
	routeTablesInUse map[int]bool
	fwMarksInUse     map[uint32]bool
}

func (f fakeProbe) SubnetInUse(_ context.Context, subnet string) (bool, error) {
	return f.subnetsInUse[subnet], nil
}

func (f fakeProbe) RouteTableInUse(_ context.Context, routeTable int) (bool, error) {
	return f.routeTablesInUse[routeTable], nil
}

func (f fakeProbe) FWMarkInUse(_ context.Context, fwMark uint32) (bool, error) {
	return f.fwMarksInUse[fwMark], nil
}
