package services

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseDomainList(t *testing.T) {
	cm := NewConfigManager()

	t.Run("splits domains and suffixes", func(t *testing.T) {
		in := "rutracker.org\n.youtube.com\n# comment\nrutor.is # inline\n\n.googlevideo.com\nrutracker.org\n"
		domains, suffixes, err := cm.ParseDomainList(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"rutracker.org", "rutor.is"}; !reflect.DeepEqual(domains, want) {
			t.Errorf("domains = %v, want %v", domains, want)
		}
		if want := []string{".youtube.com", ".googlevideo.com"}; !reflect.DeepEqual(suffixes, want) {
			t.Errorf("suffixes = %v, want %v", suffixes, want)
		}
	})

	t.Run("invalid entries reported with line numbers", func(t *testing.T) {
		in := "rutracker.org\nnot a domain\nхост.без.ascii"
		_, _, err := cm.ParseDomainList(in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 3") {
			t.Errorf("error should mention lines 2 and 3: %v", err)
		}
	})

	t.Run("empty list is valid", func(t *testing.T) {
		domains, suffixes, err := cm.ParseDomainList("# only comments\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(domains) != 0 || len(suffixes) != 0 {
			t.Errorf("expected empty lists, got %v / %v", domains, suffixes)
		}
	})
}

func TestDnsBoxConfigRoundTrip(t *testing.T) {
	cm := NewConfigManager()
	config := []byte(`{
	  "server": {"address": ["127.0.0.1:953"], "log": "debug"},
	  "dns": {"timeout": 5},
	  "ipset": {"ipv4name": "vpn_domains", "ipv6name": "vpn_domains6"},
	  "rules": {
	    "domain": ["rutor.is"],
	    "domain_suffix": [".youtube.com"]
	  }
	}`)

	text, err := cm.DomainsFromDnsBoxConfig(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "rutor.is\n.youtube.com\n" {
		t.Errorf("got %q", text)
	}

	newConfig, err := cm.ApplyDomainsToDnsBoxConfig(config, []string{"rutracker.org"}, []string{".ytimg.com", ".ggpht.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed struct {
		Server map[string]json.RawMessage `json:"server"`
		Ipset  struct {
			IPv4 string `json:"ipv4name"`
		} `json:"ipset"`
		Rules struct {
			Domain       []string `json:"domain"`
			DomainSuffix []string `json:"domain_suffix"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(newConfig), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed.Ipset.IPv4 != "vpn_domains" {
		t.Error("other config sections must be preserved")
	}
	if want := []string{"rutracker.org"}; !reflect.DeepEqual(parsed.Rules.Domain, want) {
		t.Errorf("domain = %v, want %v", parsed.Rules.Domain, want)
	}
	if want := []string{".ytimg.com", ".ggpht.com"}; !reflect.DeepEqual(parsed.Rules.DomainSuffix, want) {
		t.Errorf("domain_suffix = %v, want %v", parsed.Rules.DomainSuffix, want)
	}
}

func TestDomainListText(t *testing.T) {
	got := DomainListText([]string{"rutracker.org", "rutor.is"}, []string{".youtube.com"})
	want := "rutracker.org\nrutor.is\n.youtube.com\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if DomainListText(nil, nil) != "" {
		t.Error("empty input must yield empty string")
	}
}
func TestApplyDomainsToEmptyRules(t *testing.T) {
	cm := NewConfigManager()
	newConfig, err := cm.ApplyDomainsToDnsBoxConfig([]byte(`{"server":{}}`), nil, []string{".youtube.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed struct {
		Rules struct {
			Domain       []string `json:"domain"`
			DomainSuffix []string `json:"domain_suffix"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(newConfig), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed.Rules.Domain == nil || len(parsed.Rules.Domain) != 0 {
		t.Errorf("domain should be empty array, got %v", parsed.Rules.Domain)
	}
	if want := []string{".youtube.com"}; !reflect.DeepEqual(parsed.Rules.DomainSuffix, want) {
		t.Errorf("domain_suffix = %v, want %v", parsed.Rules.DomainSuffix, want)
	}
}
