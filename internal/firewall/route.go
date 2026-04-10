package firewall

import (
	"errors"
	"fmt"
)

func BuildPolicyRoutingPlan(fwMark uint32, routeTable int) ([]string, error) {
	if fwMark == 0 {
		return nil, errors.New("fwmark must be non-zero")
	}
	if routeTable <= 0 {
		return nil, errors.New("route table must be positive")
	}

	return []string{
		fmt.Sprintf("ip rule add fwmark %d lookup %d", fwMark, routeTable),
		fmt.Sprintf("ip route add local 0.0.0.0/0 dev lo table %d", routeTable),
	}, nil
}
