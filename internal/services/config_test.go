package services

import (
	"strings"
	"testing"

	"github.com/romanychev/be3600/embedded"
)

func TestApplyOutboundsWithEmbeddedConfig(t *testing.T) {
	cm := NewConfigManager()
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@10.0.0.1:443?security=reality&sni=vk.com&fp=chrome&pbk=somekey&sid=f0be&flow=xtls-rprx-vision#MyServer"

	if !cm.OutboundsCheck(link) {
		t.Fatal("OutboundsCheck rejected a valid vless link")
	}
	if cm.OutboundsCheck("garbage text") {
		t.Fatal("OutboundsCheck accepted garbage")
	}

	result, err := cm.ApplyOutbounds(embedded.SingBoxConfig, link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"MyServer"`) {
		t.Error("result does not contain new outbound tag")
	}
	if strings.Contains(result, `"test"`) {
		t.Error("placeholder outbound 'test' was not removed")
	}
	for _, section := range []string{`"inbounds"`, `"route"`, `"dns"`, `"mainSelector"`, `"mainUrlTest"`} {
		if !strings.Contains(result, section) {
			t.Errorf("result lost config section %s", section)
		}
	}
}
