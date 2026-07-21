package router

import (
	"regexp"
	"strings"
	"testing"
)

// applyDnsmasq mirrors ChangeDnsMasqConfig: build the edits and apply them
// the same line-based way replaceRemoteFileRegex does on the router.
func applyDnsmasq(t *testing.T, content string, add bool) string {
	t.Helper()
	patterns := buildDnsmasqModifications(content, add)
	repl := map[*regexp.Regexp]string{}
	for p, r := range patterns {
		repl[regexp.MustCompile(p)] = r
	}
	out, _ := applyLineReplacements(content, repl)
	return out
}

const stockDhcp = `config dnsmasq
        option domainneeded '1'
        option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
        list server '127.0.0.1#953'
        list server '1.1.1.1'
        list server '8.8.8.8'

config dhcp 'lan'
        option interface 'lan'
`

func TestDnsmasqAddMakesDnsBoxSoleUpstream(t *testing.T) {
	// Config that already had the public resolvers but not dns-box yet.
	content := strings.Replace(stockDhcp, "        list server '127.0.0.1#953'\n", "", 1)

	out := applyDnsmasq(t, content, true)

	if !strings.Contains(out, "list server '127.0.0.1#953'") {
		t.Error("dns-box upstream must be present")
	}
	if !strings.Contains(out, "option noresolv '1'") {
		t.Error("noresolv must be set")
	}
	if !strings.Contains(out, "option cachesize '0'") {
		t.Errorf("dnsmasq cache must be disabled, got:\n%s", out)
	}
	if strings.Contains(out, "list server '1.1.1.1'") || strings.Contains(out, "list server '8.8.8.8'") {
		t.Errorf("public resolvers must be removed, got:\n%s", out)
	}
}

func TestDnsmasqAddReplacesExistingCachesize(t *testing.T) {
	content := `config dnsmasq
        option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
        option cachesize '150'
        list server '127.0.0.1#953'
        option noresolv '1'
`
	out := applyDnsmasq(t, content, true)

	if strings.Contains(out, "option cachesize '150'") {
		t.Errorf("existing cachesize must be overwritten, got:\n%s", out)
	}
	if strings.Count(out, "option cachesize") != 1 || !strings.Contains(out, "option cachesize '0'") {
		t.Errorf("expected exactly one cachesize '0', got:\n%s", out)
	}
}

func TestDnsmasqAddIsIdempotent(t *testing.T) {
	// Already correct: only dns-box, noresolv set, cache off, no public resolvers.
	content := `config dnsmasq
        option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
        option noresolv '1'
        option cachesize '0'
        list server '127.0.0.1#953'
`
	if mods := buildDnsmasqModifications(content, true); len(mods) != 0 {
		t.Errorf("expected no changes on an already-correct config, got %v", mods)
	}
}

func TestDnsmasqRemoveRestoresPublicResolvers(t *testing.T) {
	// State after install: dns-box only, cache disabled.
	installed := `config dnsmasq
        option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
        option noresolv '1'
        option cachesize '0'
        list server '127.0.0.1#953'

config dhcp 'lan'
`
	out := applyDnsmasq(t, installed, false)

	if strings.Contains(out, "list server '127.0.0.1#953'") {
		t.Error("dns-box upstream must be removed on uninstall")
	}
	if strings.Contains(out, "option noresolv '1'") {
		t.Error("noresolv must be cleared on uninstall")
	}
	if strings.Contains(out, "option cachesize '0'") {
		t.Error("cache-disable must be cleared on uninstall")
	}
	if !strings.Contains(out, "list server '1.1.1.1'") || !strings.Contains(out, "list server '8.8.8.8'") {
		t.Errorf("public resolvers must be restored, got:\n%s", out)
	}
}
