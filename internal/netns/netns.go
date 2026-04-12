package netns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

type Resources struct {
	NetNS      string
	HostVeth   string
	GuestVeth  string
	TableName  string
	FWMark     uint32
	RouteTable int
	SubnetCIDR string
}

type SetupPlan struct {
	Commands    []string
	Teardown    []string
	GatewayCIDR string
	SandboxCIDR string
	GatewayIP   string
	SandboxIP   string
}

type Probe interface {
	SubnetInUse(ctx context.Context, subnet string) (bool, error)
	RouteTableInUse(ctx context.Context, routeTable int) (bool, error)
	FWMarkInUse(ctx context.Context, fwMark uint32) (bool, error)
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

func AllocateResources(ctx context.Context, runtimeID string, subnetPool string, probe Probe) (Resources, error) {
	resources, err := ResourcesForRuntimeID(runtimeID)
	if err != nil {
		return Resources{}, err
	}
	if probe == nil {
		probe = systemProbe{}
	}

	subnetCIDR, err := allocateSubnetCIDR(ctx, strings.TrimSpace(subnetPool), probe)
	if err != nil {
		return Resources{}, err
	}
	routeTable, err := allocateRouteTable(ctx, probe)
	if err != nil {
		return Resources{}, err
	}
	fwMark, err := allocateFWMark(ctx, probe)
	if err != nil {
		return Resources{}, err
	}

	resources.SubnetCIDR = subnetCIDR
	resources.RouteTable = routeTable
	resources.FWMark = fwMark
	return resources, nil
}

func BuildSetupPlan(resources Resources) (SetupPlan, error) {
	trimmed := strings.TrimSpace(resources.SubnetCIDR)
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

type systemProbe struct{}

func (systemProbe) SubnetInUse(ctx context.Context, subnet string) (bool, error) {
	candidate, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return false, fmt.Errorf("parse subnet %q: %w", subnet, err)
	}
	candidate = candidate.Masked()

	for _, command := range [][]string{
		{"ip", "-o", "addr", "show"},
		{"ip", "-o", "route", "show"},
	} {
		out, err := runOutput(ctx, command[0], command[1:]...)
		if err != nil {
			return false, err
		}
		for _, prefix := range parseIPv4Prefixes(out) {
			if prefixesOverlap(candidate, prefix) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (systemProbe) RouteTableInUse(ctx context.Context, routeTable int) (bool, error) {
	routeOut, err := runOutput(ctx, "ip", "-o", "route", "show", "table", strconv.Itoa(routeTable))
	if err != nil {
		if outputLooksLikeMissingResource(routeOut) {
			routeOut = ""
		} else {
			return false, err
		}
	}
	if strings.TrimSpace(routeOut) != "" {
		return true, nil
	}

	ruleOut, err := runOutput(ctx, "ip", "-o", "rule", "show", "table", strconv.Itoa(routeTable))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(ruleOut) != "", nil
}

func (systemProbe) FWMarkInUse(ctx context.Context, fwMark uint32) (bool, error) {
	out, err := runOutput(ctx, "ip", "-o", "rule", "show", "fwmark", fmt.Sprintf("0x%x", fwMark))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

func allocateSubnetCIDR(ctx context.Context, subnetPool string, probe Probe) (string, error) {
	pool, err := netip.ParsePrefix(strings.TrimSpace(subnetPool))
	if err != nil {
		return "", fmt.Errorf("parse subnet pool %q: %w", subnetPool, err)
	}
	pool = pool.Masked()
	if !pool.Addr().Is4() {
		return "", fmt.Errorf("subnet pool %q must be ipv4", subnetPool)
	}
	if pool.Bits() > 30 {
		return "", fmt.Errorf("subnet pool %q must be /30 or larger", subnetPool)
	}

	start := addrToUint32(pool.Addr())
	last := lastAddr(pool)
	for base := start; base+3 <= addrToUint32(last); base += 4 {
		candidate := netip.PrefixFrom(uint32ToAddr(base), 30).Masked()
		if !pool.Contains(candidate.Addr()) || !pool.Contains(lastAddr(candidate)) {
			continue
		}
		inUse, err := probe.SubnetInUse(ctx, candidate.String())
		if err != nil {
			return "", err
		}
		if !inUse {
			return candidate.String(), nil
		}
	}
	return "", fmt.Errorf("no free /30 subnet available in pool %q", subnetPool)
}

func allocateRouteTable(ctx context.Context, probe Probe) (int, error) {
	for candidate := 10000; candidate < 60000; candidate++ {
		inUse, err := probe.RouteTableInUse(ctx, candidate)
		if err != nil {
			return 0, err
		}
		if !inUse {
			return candidate, nil
		}
	}
	return 0, errors.New("no free route table available")
}

func allocateFWMark(ctx context.Context, probe Probe) (uint32, error) {
	for candidate := uint32(0x100); candidate < 0x10000; candidate++ {
		inUse, err := probe.FWMarkInUse(ctx, candidate)
		if err != nil {
			return 0, err
		}
		if !inUse {
			return candidate, nil
		}
	}
	return 0, errors.New("no free fwmark available")
}

func prefixString(addr netip.Addr, bits int) string {
	return addr.String() + "/" + fmt.Sprintf("%d", bits)
}

func runOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return combined.String(), err
	}
	return combined.String(), nil
}

func outputLooksLikeMissingResource(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "fib table does not exist")
}

func parseIPv4Prefixes(output string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, field := range strings.Fields(output) {
		candidate := strings.Trim(field, " ,[]")
		prefix, err := netip.ParsePrefix(candidate)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes
}

func prefixesOverlap(a netip.Prefix, b netip.Prefix) bool {
	a = a.Masked()
	b = b.Masked()
	return a.Contains(b.Addr()) ||
		b.Contains(a.Addr()) ||
		a.Contains(lastAddr(b)) ||
		b.Contains(lastAddr(a))
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	base := addrToUint32(prefix.Masked().Addr())
	hostBits := 32 - prefix.Bits()
	if hostBits <= 0 {
		return prefix.Addr()
	}
	return uint32ToAddr(base + (1 << hostBits) - 1)
}

func addrToUint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func uint32ToAddr(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
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
