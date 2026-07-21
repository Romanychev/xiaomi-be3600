package services

import (
	"strings"
	"testing"
)

func TestNormalizeBypassList(t *testing.T) {
	cm := NewConfigManager()

	t.Run("valid entries", func(t *testing.T) {
		in := "1.2.3.4\n10.10.0.0/16\n# comment line\n2a02:6b8::1\n2a02:6b8::/32\n\n  8.8.8.8  # inline comment\n"
		got, err := cm.NormalizeBypassList(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "1.2.3.4\n10.10.0.0/16\n2a02:6b8::1\n2a02:6b8::/32\n8.8.8.8\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("invalid entries reported with line numbers", func(t *testing.T) {
		in := "1.2.3.4\nnot-an-ip\n10.0.0.0/33"
		_, err := cm.NormalizeBypassList(in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 3") {
			t.Errorf("error should mention lines 2 and 3: %v", err)
		}
	})

	t.Run("empty list clears file", func(t *testing.T) {
		got, err := cm.NormalizeBypassList("\n# only comments\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})
}
