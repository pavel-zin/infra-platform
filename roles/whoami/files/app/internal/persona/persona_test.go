package persona

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestWordListsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range adjectives {
		if w == "" || seen[w] {
			t.Fatalf("adjective %q missing or repeated", w)
		}
		seen[w] = true
	}
	for _, c := range colors {
		if c.name == "" || seen[c.name] || len(c.hex) != 7 {
			t.Fatalf("colour %+v missing, repeated or malformed", c)
		}
		seen[c.name] = true
	}
	for _, a := range animals {
		if a.name == "" || a.emoji == "" || seen[a.name] {
			t.Fatalf("animal %+v missing or repeated", a)
		}
		seen[a.name] = true
	}
}

func id(s string) [16]byte {
	sum := sha256.Sum256([]byte(s))
	return [16]byte(sum[:16])
}

func TestDeterministicAndSpread(t *testing.T) {
	a, b := From(id("one")), From(id("one"))
	if a != b {
		t.Fatal("same ID must give the same persona")
	}
	names := map[string]int{}
	codes := map[string]bool{}
	for i := range 2000 {
		p := From(id(strings.Repeat("x", i)))
		names[p.Name]++
		if codes[p.Code] {
			t.Fatalf("code collision after %d IDs", i)
		}
		codes[p.Code] = true
		if p.Color == p.Color2 {
			t.Fatalf("persona %v has identical colours", p)
		}
		r := p.Rosette
		if r.OuterLobes < 9 || r.OuterLobes > 24 || r.InnerStrands < 3 || r.StarPoints < 3 {
			t.Fatalf("rosette out of range: %+v", r)
		}
	}
	// 2000 draws from ~500k names: a handful of repeats at most.
	if len(names) < 1990 {
		t.Fatalf("only %d distinct names out of 2000", len(names))
	}
}

func TestMRZ(t *testing.T) {
	p := From(id("browser"))
	born := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	m := MRZ(p, id("browser"), id("device"), born, born.AddDate(0, 0, 180))
	for i, l := range m {
		if len(l) != 44 {
			t.Fatalf("line %d has %d characters: %q", i+1, len(l), l)
		}
		for _, c := range l {
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '<') {
				t.Fatalf("line %d has invalid character %q", i+1, c)
			}
		}
	}
	if !strings.HasPrefix(m[0], "P<WWW"+strings.ToUpper(p.Animal)+"<<") {
		t.Fatalf("line 1 = %q", m[0])
	}
	if m[1][13:19] != "261012" || m[1][21:27] != "270410" {
		t.Fatalf("dates in line 2 = %q", m[1])
	}
}

func TestCheckDigit(t *testing.T) {
	// Worked examples from ICAO Doc 9303 Part 3.
	for in, want := range map[string]string{"L898902C3": "6", "740812": "2", "120415": "9", "ZE184226B<<<<<": "1"} {
		if got := checkDigit(in); got != want {
			t.Errorf("checkDigit(%q) = %s, want %s", in, got, want)
		}
	}
}
