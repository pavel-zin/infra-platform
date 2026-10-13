package geo

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOffsets(t *testing.T) {
	summer := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if off, ok := ZoneOffset("Europe/Paris", summer); !ok || off != 2*3600 {
		t.Fatalf("Paris = %d %v", off, ok)
	}
	// Legacy alias that Chromium still reports.
	if off, ok := ZoneOffset("Asia/Calcutta", summer); !ok || off != 5*3600+1800 {
		t.Fatalf("Calcutta = %d %v", off, ok)
	}
	if _, ok := ZoneOffset("../../etc/passwd", summer); ok {
		t.Fatal("path-like zone names must be rejected")
	}
	us := CountryOffsets("us", summer)
	if !slices.Contains(us, -4*3600) || !slices.Contains(us, -7*3600) || slices.Contains(us, 2*3600) {
		t.Fatalf("US offsets = %v", us)
	}
	if CountryOffsets("ZZ", summer) != nil {
		t.Fatal("unknown country should have no offsets")
	}
}

func TestParseExitList(t *testing.T) {
	set := parseExitList(strings.NewReader("# comment\n185.220.101.1\n\n2001:db8::1\nnot-an-ip\n"))
	if len(set) != 2 {
		t.Fatalf("set = %v", set)
	}
}
