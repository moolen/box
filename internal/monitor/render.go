package monitor

import (
	"fmt"
	"sort"
	"strings"
)

func RenderSummary(snapshot Snapshot) string {
	var b strings.Builder
	b.WriteString("Monitor summary\n")

	total := snapshot.Total
	if total == 0 {
		total = countPrimaryEvents(snapshot)
	}
	wroteSection := false

	if len(snapshot.DNS) > 0 {
		wroteSection = true
		b.WriteString("DNS:\n")
		keys := sortedHosts(snapshot.DNS)
		for _, host := range keys {
			row := snapshot.DNS[host]
			b.WriteString(fmt.Sprintf("  %s [%s]: %d%s\n", host, strings.ToUpper(string(row.Verdict)), row.Count, formatReasonSuffix(row)))
		}
	}

	if len(snapshot.HTTP) > 0 {
		wroteSection = true
		b.WriteString("HTTP:\n")
		keys := sortedHTTPKeys(snapshot.HTTP)
		for _, key := range keys {
			row := snapshot.HTTP[key]
			b.WriteString(fmt.Sprintf("  %s %s [%s]: %d%s\n", key.Method, key.Hostname, strings.ToUpper(string(row.Verdict)), row.Count, formatReasonSuffix(row)))
		}
	}

	if len(snapshot.TLS) > 0 {
		wroteSection = true
		b.WriteString("TLS:\n")
		keys := sortedHosts(snapshot.TLS)
		for _, host := range keys {
			row := snapshot.TLS[host]
			b.WriteString(fmt.Sprintf("  %s [%s]: %d%s\n", host, strings.ToUpper(string(row.Verdict)), row.Count, formatReasonSuffix(row)))
		}
	}

	if len(snapshot.ICMP) > 0 {
		wroteSection = true
		b.WriteString("ICMP:\n")
		keys := sortedICMPKeys(snapshot.ICMP)
		for _, key := range keys {
			row := snapshot.ICMP[key]
			b.WriteString(fmt.Sprintf("  %s [%s]: %d%s\n", formatICMPKey(key), strings.ToUpper(string(row.Verdict)), row.Count, formatReasonSuffix(row)))
		}
	}
	if !wroteSection {
		b.WriteString("no traffic captured\n")
	}

	b.WriteString(fmt.Sprintf("Total events: %d\n", total))
	return b.String()
}

func countPrimaryEvents(snapshot Snapshot) int {
	total := 0
	for _, row := range snapshot.DNS {
		total += row.Count
	}
	for _, row := range snapshot.HTTP {
		total += row.Count
	}
	for _, row := range snapshot.TLS {
		total += row.Count
	}
	for _, row := range snapshot.ICMP {
		total += row.Count
	}
	return total
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

func sortedICMPKeys(m map[ICMPKey]Row) []ICMPKey {
	keys := make([]ICMPKey, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i int, j int) bool {
		if keys[i].Target != keys[j].Target {
			return keys[i].Target < keys[j].Target
		}
		if keys[i].Type != keys[j].Type {
			return keys[i].Type < keys[j].Type
		}
		if keys[i].HasCode != keys[j].HasCode {
			return !keys[i].HasCode && keys[j].HasCode
		}
		return keys[i].Code < keys[j].Code
	})
	return keys
}

func formatICMPKey(key ICMPKey) string {
	label := fmt.Sprintf("TYPE %d", key.Type)
	if key.HasCode {
		label += fmt.Sprintf(" CODE %d", key.Code)
	}
	return label + " " + key.Target
}

func formatReasonSuffix(row Row) string {
	if strings.TrimSpace(row.Reason) == "" {
		return ""
	}
	return " (" + row.Reason + ")"
}
