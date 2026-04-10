package netns

import (
	"errors"
	"hash/fnv"
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
