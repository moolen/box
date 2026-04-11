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
			row := snapshot.DNS[host]
			total += row.Count
			b.WriteString(fmt.Sprintf("  %s [%s]: %d\n", host, row.Verdict, row.Count))
		}
	}

	if len(snapshot.HTTP) > 0 {
		b.WriteString("HTTP:\n")
		keys := sortedHTTPKeys(snapshot.HTTP)
		for _, key := range keys {
			row := snapshot.HTTP[key]
			total += row.Count
			b.WriteString(fmt.Sprintf("  %s %s [%s]: %d\n", key.Method, key.Hostname, row.Verdict, row.Count))
		}
	}

	if len(snapshot.TLS) > 0 {
		b.WriteString("TLS:\n")
		keys := sortedHosts(snapshot.TLS)
		for _, host := range keys {
			row := snapshot.TLS[host]
			total += row.Count
			b.WriteString(fmt.Sprintf("  %s [%s]: %d\n", host, row.Verdict, row.Count))
		}
	}

	b.WriteString(fmt.Sprintf("Total events: %d\n", total))
	return b.String()
}

func sortedHosts(m map[string]Row) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedHTTPKeys(m map[HTTPKey]Row) []HTTPKey {
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
