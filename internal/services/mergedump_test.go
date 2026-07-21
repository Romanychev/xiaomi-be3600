package services

import (
	"os"
	"testing"

	"github.com/romanychev/be3600/embedded"
)

// TestDumpMergedConfig writes the result of ApplyOutbounds to the path in
// MERGED_CONFIG_OUT so it can be validated with `sing-box check` externally.
func TestDumpMergedConfig(t *testing.T) {
	out := os.Getenv("MERGED_CONFIG_OUT")
	if out == "" {
		t.Skip("MERGED_CONFIG_OUT not set")
	}
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@10.0.0.1:443?security=reality&sni=vk.com&fp=chrome&pbk=t4xj72RwiT_AEeK0uzQZy4ixzkkPBfttu_SSCmJGbwg&sid=f0be&flow=xtls-rprx-vision&type=tcp#MyServer\n" +
		"ss://YWVzLTI1Ni1nY206cGFzczEyMw==@5.6.7.8:8388#ss1\n" +
		"trojan://pw123@9.9.9.9:443?sni=example.com&alpn=h2,http/1.1#tj1"
	cm := NewConfigManager()
	merged, err := cm.ApplyOutbounds(embedded.SingBoxConfig, link)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(merged), 0644); err != nil {
		t.Fatal(err)
	}
}
