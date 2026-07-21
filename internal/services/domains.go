package services

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Lines with a leading dot become rules.domain_suffix entries, the rest go
// to rules.domain — the same convention the dns-box config itself uses.
var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// ParseDomainList validates a user supplied domain list (one domain per
// line, leading '.' marks a suffix rule, '#' starts a comment) and returns
// the exact-match domains and suffixes separately.
func (cm *ConfigManager) ParseDomainList(text string) (domains, suffixes []string, err error) {
	var bad []string
	seen := map[string]bool{}

	for i, raw := range strings.Split(text, "\n") {
		line := raw
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		isSuffix := strings.HasPrefix(line, ".")
		if !domainRe.MatchString(strings.TrimPrefix(line, ".")) {
			bad = append(bad, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(raw)))
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true

		if isSuffix {
			suffixes = append(suffixes, line)
		} else {
			domains = append(domains, line)
		}
	}

	if len(bad) > 0 {
		return nil, nil, fmt.Errorf("invalid entries: %s", strings.Join(bad, "; "))
	}
	return domains, suffixes, nil
}

// DomainListText renders a domain/suffix pair back into the editable text
// format (exact-match domains first, then suffixes), one per line. This is
// what gets stored in the persistent vpn_domains.txt list. Empty input yields
// an empty string.
func DomainListText(domains, suffixes []string) string {
	lines := make([]string, 0, len(domains)+len(suffixes))
	lines = append(lines, domains...)
	lines = append(lines, suffixes...)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// DomainsFromDnsBoxConfig renders rules.domain and rules.domain_suffix from
// a dns-box config as an editable text list.
func (cm *ConfigManager) DomainsFromDnsBoxConfig(config []byte) (string, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("invalid dns-box config: %w", err)
	}

	var rules struct {
		Domain       []string `json:"domain"`
		DomainSuffix []string `json:"domain_suffix"`
	}
	if raw, ok := cfg["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return "", fmt.Errorf("invalid rules section: %w", err)
		}
	}

	lines := make([]string, 0, len(rules.Domain)+len(rules.DomainSuffix))
	lines = append(lines, rules.Domain...)
	lines = append(lines, rules.DomainSuffix...)
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ApplyDomainsToDnsBoxConfig replaces rules.domain and rules.domain_suffix
// in a dns-box config, leaving every other section untouched.
func (cm *ConfigManager) ApplyDomainsToDnsBoxConfig(config []byte, domains, suffixes []string) (string, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("invalid dns-box config: %w", err)
	}

	rules := map[string]json.RawMessage{}
	if raw, ok := cfg["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return "", fmt.Errorf("invalid rules section: %w", err)
		}
	}

	if domains == nil {
		domains = []string{}
	}
	if suffixes == nil {
		suffixes = []string{}
	}
	domainsJSON, _ := json.Marshal(domains)
	suffixesJSON, _ := json.Marshal(suffixes)
	rules["domain"] = domainsJSON
	rules["domain_suffix"] = suffixesJSON

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	cfg["rules"] = rulesJSON

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
