package converter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/romanychev/be3600/internal/ray2sing/option"
)

func TestOutboundsVless(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&sni=cdn.example.com&fp=chrome&pbk=publickey123&sid=6ba85179&type=grpc&serviceName=grpcsvc&flow=xtls-rprx-vision#MyServer"
	outbounds, err := Outbounds(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %d", len(outbounds))
	}
	if outbounds[0].Type != "vless" || outbounds[0].Tag != "MyServer" {
		t.Fatalf("unexpected type/tag: %q %q", outbounds[0].Type, outbounds[0].Tag)
	}
	data, err := json.Marshal(outbounds[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"server":"example.com"`, `"server_port":443`,
		`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"`,
		`"flow":"xtls-rprx-vision"`, `"public_key":"publickey123"`,
		`"fingerprint":"chrome"`, `"service_name":"grpcsvc"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("marshaled outbound missing %s: %s", want, data)
		}
	}
}

// Всё, кроме vless, отклоняется: на роутере slim-сборка sing-box без
// других протоколов, и молча принятая ссылка означала бы нерабочий конфиг.
func TestOutboundsRejectsNonVless(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"vm1","add":"1.2.3.4","port":"8080","id":"uuid-1"}`
	for name, link := range map[string]string{
		"vmess":   "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)),
		"ss":      "ss://" + base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:pass123")) + "@5.6.7.8:8388#ss1",
		"trojan":  "trojan://password@example.com:443#t1",
		"garbage": "http://not-a-proxy-link",
	} {
		if _, err := Outbounds(link); err == nil {
			t.Errorf("expected error for %s link", name)
		}
	}
	if _, err := Outbounds("   \n  "); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestOptionsRoundTripPreservesConfig(t *testing.T) {
	config := `{
		"log": {"level": "info"},
		"dns": {"servers": [{"tag": "dns-remote", "address": "8.8.8.8"}]},
		"outbounds": [
			{"type": "selector", "tag": "proxy", "outbounds": ["test"], "default": "test"},
			{"type": "urltest", "tag": "auto", "outbounds": ["test"], "url": "https://www.gstatic.com/generate_204"},
			{"type": "direct", "tag": "direct"}
		],
		"route": {"final": "proxy"}
	}`
	var opts option.Options
	if err := opts.UnmarshalJSON([]byte(config)); err != nil {
		t.Fatal(err)
	}
	if len(opts.Outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(opts.Outbounds))
	}
	opts.Outbounds[0].SelectorOptions.Outbounds = []string{"MyServer"}
	opts.Outbounds[1].URLTestOptions.Outbounds = []string{"MyServer"}

	data, err := json.MarshalIndent(opts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, want := range []string{
		`"level": "info"`, `"final": "proxy"`, `"address": "8.8.8.8"`,
		`"default": "test"`, `"url": "https://www.gstatic.com/generate_204"`,
		`"MyServer"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("round-tripped config missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"outbounds": [`+"\n"+`      "test"`) {
		t.Errorf("selector still references old outbound:\n%s", out)
	}
}
