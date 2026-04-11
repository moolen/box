package monitor

import (
	"fmt"
	"sort"
	"strings"
)

func RenderSummary(snapshot Snapshot) string {
	var b strings.Builder
	b.WriteString("Monitor summary\n")

	total := 0

	if len(snapshot.DNS) > 0 {
		b.WriteString("DNS:\n")
		keys := sortedHosts(snapshot.DNS)
		for _, host := range keys {
			count := snapshot.DNS[host]
			total += count
			b.WriteString(fmt.Sprintf("  %s: %d\n", host, count))
		}
	}

	if len(snapshot.HTTP) > 0 {
		b.WriteString("HTTP:\n")
		keys := sortedHTTPKeys(snapshot.HTTP)
		for _, key := range keys {
			count := snapshot.HTTP[key]
			total += count
			b.WriteString(fmt.Sprintf("  %s %s: %d\n", key.Method, key.Hostname, count))
		}
	}

	if len(snapshot.TLS) > 0 {
		b.WriteString("TLS:\n")
		keys := sortedHosts(snapshot.TLS)
		for _, host := range keys {
			count := snapshot.TLS[host]
			total += count
			b.WriteString(fmt.Sprintf("  %s: %d\n", host, count))
		}
	}

	b.WriteString(fmt.Sprintf("Total events: %d\n", total))
	return b.String()
}

func sortedHosts(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedHTTPKeys(m map[HTTPKey]int) []HTTPKey {
	keys := make([]HTTPKey, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i int, j int) bool {
		if keys[i].Method != keys[j].Method {
			return keys[i].Method < keys[j].Method
		}
		return keys[i].Hostname < keys[j].Hostname
	})
	return keys
}
