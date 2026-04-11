package netns

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestRuntimeIDProducesDeterministicResourceNames(t *testing.T) {
	first, err := ResourcesForRuntimeID("runtime-abc-123")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}
	second, err := ResourcesForRuntimeID("runtime-abc-123")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}
	other, err := ResourcesForRuntimeID("runtime-def-456")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}

	if first != second {
		t.Fatalf("same runtime id must produce identical resources: first=%+v second=%+v", first, second)
	}
	if first == other {
		t.Fatalf("different runtime ids must not produce identical resources: first=%+v other=%+v", first, other)
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

func TestBuildSetupPlanAssignsGatewayAndSandboxAddress(t *testing.T) {
	resources, err := ResourcesForRuntimeID("runtime-abc-123")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}

	plan, err := BuildSetupPlan(resources, "100.96.0.0/30")
	if err != nil {
		t.Fatalf("BuildSetupPlan() error: %v", err)
	}

	if plan.GatewayCIDR != "100.96.0.1/30" {
		t.Fatalf("GatewayCIDR = %q, want %q", plan.GatewayCIDR, "100.96.0.1/30")
	}
	if plan.SandboxCIDR != "100.96.0.2/30" {
		t.Fatalf("SandboxCIDR = %q, want %q", plan.SandboxCIDR, "100.96.0.2/30")
	}
	if plan.GatewayIP != "100.96.0.1" {
		t.Fatalf("GatewayIP = %q, want %q", plan.GatewayIP, "100.96.0.1")
	}
	if plan.SandboxIP != "100.96.0.2" {
		t.Fatalf("SandboxIP = %q, want %q", plan.SandboxIP, "100.96.0.2")
	}

	wantCommands := []string{
		fmt.Sprintf("ip netns add %s", resources.NetNS),
		fmt.Sprintf("ip link add %s type veth peer name %s", resources.HostVeth, resources.GuestVeth),
		fmt.Sprintf("ip link set %s netns %s", resources.GuestVeth, resources.NetNS),
		fmt.Sprintf("ip addr add 100.96.0.1/30 dev %s", resources.HostVeth),
		fmt.Sprintf("ip netns exec %s ip addr add 100.96.0.2/30 dev %s", resources.NetNS, resources.GuestVeth),
		fmt.Sprintf("ip netns exec %s ip route add default via 100.96.0.1 dev %s", resources.NetNS, resources.GuestVeth),
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
