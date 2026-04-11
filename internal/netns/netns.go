package netns

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"strings"
)

type Resources struct {
	NetNS      string
	HostVeth   string
	GuestVeth  string
	TableName  string
	FWMark     uint32
	RouteTable int
}

type SetupPlan struct {
	Commands    []string
	Teardown    []string
	GatewayCIDR string
	SandboxCIDR string
	GatewayIP   string
	SandboxIP   string
}

func ResourcesForRuntimeID(runtimeID string) (Resources, error) {
	trimmed := strings.TrimSpace(runtimeID)
	if trimmed == "" {
		return Resources{}, errors.New("runtime id is required")
	}

	token := hashToken(trimmed)
	return Resources{
		NetNS:      "box-" + token,
		HostVeth:   "vethh" + token,
		GuestVeth:  "vethg" + token,
		TableName:  "box_" + token,
		FWMark:     0x100 + (hashUint32(trimmed) & 0xFFFF),
		RouteTable: 10000 + int(hashUint32(trimmed)%50000),
	}, nil
}

func BuildSetupPlan(resources Resources, subnet string) (SetupPlan, error) {
	trimmed := strings.TrimSpace(subnet)
	if trimmed == "" {
		return SetupPlan{}, errors.New("subnet is required")
	}

	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return SetupPlan{}, fmt.Errorf("parse subnet %q: %w", trimmed, err)
	}

	addr := prefix.Masked().Addr()
	if !addr.Is4() {
		return SetupPlan{}, fmt.Errorf("subnet %q must be ipv4", trimmed)
	}

	gateway := addr.Next()
	sandbox := gateway.Next()
	if !prefix.Contains(gateway) || !prefix.Contains(sandbox) {
		return SetupPlan{}, fmt.Errorf("subnet %q does not have enough usable addresses", trimmed)
	}

	gatewayCIDR := prefixString(gateway, prefix.Bits())
	sandboxCIDR := prefixString(sandbox, prefix.Bits())

	return SetupPlan{
		Commands: []string{
			fmt.Sprintf("ip netns add %s", resources.NetNS),
			fmt.Sprintf("ip link add %s type veth peer name %s", resources.HostVeth, resources.GuestVeth),
			fmt.Sprintf("ip link set %s netns %s", resources.GuestVeth, resources.NetNS),
			fmt.Sprintf("ip addr add %s dev %s", gatewayCIDR, resources.HostVeth),
			fmt.Sprintf("ip link set %s up", resources.HostVeth),
			fmt.Sprintf("ip netns exec %s ip link set lo up", resources.NetNS),
			fmt.Sprintf("ip netns exec %s ip addr add %s dev %s", resources.NetNS, sandboxCIDR, resources.GuestVeth),
			fmt.Sprintf("ip netns exec %s ip link set %s up", resources.NetNS, resources.GuestVeth),
			fmt.Sprintf("ip netns exec %s ip route add default via %s dev %s", resources.NetNS, gateway.String(), resources.GuestVeth),
		},
		Teardown: []string{
			fmt.Sprintf("ip link del %s", resources.HostVeth),
			fmt.Sprintf("ip netns del %s", resources.NetNS),
		},
		GatewayCIDR: gatewayCIDR,
		SandboxCIDR: sandboxCIDR,
		GatewayIP:   gateway.String(),
		SandboxIP:   sandbox.String(),
	}, nil
}

func prefixString(addr netip.Addr, bits int) string {
	return addr.String() + "/" + fmt.Sprintf("%d", bits)
}

func hashToken(runtimeID string) string {
	const hex = "0123456789abcdef"
	v := hashUint32(runtimeID)
	out := make([]byte, 8)
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = hex[v&0xF]
		v >>= 4
	}
	return string(out)
}

func hashUint32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
