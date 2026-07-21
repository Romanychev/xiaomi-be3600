package services

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeBypassList validates a user supplied bypass list (one IPv4/IPv6
// address or CIDR subnet per line, '#' starts a comment) and returns the
// cleaned list ready to be written to the router.
func (cm *ConfigManager) NormalizeBypassList(text string) (string, error) {
	var entries []string
	var bad []string

	for i, raw := range strings.Split(text, "\n") {
		line := raw
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "/") {
			if _, _, err := net.ParseCIDR(line); err != nil {
				bad = append(bad, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(raw)))
				continue
			}
		} else if net.ParseIP(line) == nil {
			bad = append(bad, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(raw)))
			continue
		}

		entries = append(entries, line)
	}

	if len(bad) > 0 {
		return "", fmt.Errorf("invalid entries: %s", strings.Join(bad, "; "))
	}
	if len(entries) == 0 {
		return "", nil
	}
	return strings.Join(entries, "\n") + "\n", nil
}
