package router

import "testing"

func TestParseMemInfo(t *testing.T) {
	out := `MemTotal:         256000 kB
MemFree:           40000 kB
MemAvailable:     120000 kB
Buffers:            6000 kB
Cached:            50000 kB
SwapTotal:             0 kB
`
	m, err := parseMemInfo(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Total != 256000 {
		t.Errorf("Total = %d, want 256000", m.Total)
	}
	if m.Free != 40000 {
		t.Errorf("Free = %d, want 40000", m.Free)
	}
	if m.Cached != 56000 { // Cached + Buffers
		t.Errorf("Cached = %d, want 56000", m.Cached)
	}
	if m.Used != 160000 { // Total - Free - (Cached+Buffers)
		t.Errorf("Used = %d, want 160000", m.Used)
	}
	if m.Free+m.Used+m.Cached != m.Total {
		t.Errorf("Free+Used+Cached (%d) != Total (%d)", m.Free+m.Used+m.Cached, m.Total)
	}
}

func TestParseMemInfoMissingTotal(t *testing.T) {
	if _, err := parseMemInfo("MemFree: 100 kB\n"); err == nil {
		t.Fatal("expected error when MemTotal is absent")
	}
}
