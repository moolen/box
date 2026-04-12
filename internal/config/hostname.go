package config

import (
	"net"
	"strconv"
	"strings"
	"unicode"
)

// NormalizeHostname normalizes and validates hostnames used by policy and monitor paths.
// It returns an empty string when the hostname is invalid.
func NormalizeHostname(hostname string) string {
	normalized := strings.TrimSpace(hostname)
	if normalized == "" {
		return ""
	}

	if parsedHost, parsedPort, err := net.SplitHostPort(normalized); err == nil {
		port, portErr := strconv.Atoi(parsedPort)
		if portErr != nil || port < 0 || port > 65535 || parsedHost == "" {
			return ""
		}
		normalized = parsedHost
	}

	normalized = strings.ToLower(normalized)
	normalized = strings.TrimSuffix(normalized, ".")
	if !isValidHostname(normalized) {
		return ""
	}
	return normalized
}

func isValidHostname(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
