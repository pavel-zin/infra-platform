package store

import (
	"path/filepath"
	"testing"
	"time"
)

func id(b byte) ID { return ID{b} }

func TestObserveLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.gob")
	s := New(path, 180*24*time.Hour, 0)
	t0 := time.Unix(1_790_000_000, 0)
	c1, c2 := id(101), id(102)

	r := s.Observe(Observation{Browser: id(1), Device: id(9), Network: 7, Label: "Chrome on macOS", Attrs: []uint64{1, 2, 3}, Cookie: &c1, Now: t0})
	if r.Seen || r.Visits != 1 || r.Total != 1 || r.People != 1 || r.CookieSeen {
		t.Fatalf("first visit: %+v", r)
	}

	// Same browser, cookies cleared: recognized by fingerprint alone.
	r = s.Observe(Observation{Browser: id(1), Device: id(9), Network: 7, Attrs: []uint64{1, 2, 3}, Cookie: &c2, Now: t0.Add(time.Hour)})
	if !r.Seen || r.Visits != 2 || !r.First.Equal(t0) || r.People != 2 || r.CookieSeen {
		t.Fatalf("return visit: %+v", r)
	}

	// Another browser on the same device and network: it is a sibling.
	r = s.Observe(Observation{Browser: id(2), Device: id(9), Network: 7, Label: "Firefox on macOS", Attrs: []uint64{1, 4, 5}, Cookie: &c2, Now: t0.Add(2 * time.Hour)})
	if r.Seen || len(r.Siblings) != 1 || r.Siblings[0].Label != "Chrome on macOS" || r.DeviceMatches != 2 {
		t.Fatalf("second browser: %+v", r)
	}
	if !r.CookieSeen || !r.CookieMoved {
		t.Fatalf("cookie should be known and moved: %+v", r)
	}
	if r.Total != 2 || r.AttrCounts[0] != 2 || r.AttrCounts[1] != 1 {
		t.Fatalf("counts: total=%d attrs=%v", r.Total, r.AttrCounts)
	}

	// Persist and reload.
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2 := New(path, 180*24*time.Hour, 0)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if b, c := s2.Counts(); b != 2 || c != 2 {
		t.Fatalf("after reload: %d browsers %d cookies", b, c)
	}

	// Forget releases attribute counts.
	if !s2.Forget(id(1), &c1) {
		t.Fatal("forget returned false")
	}
	r = s2.Observe(Observation{Browser: id(2), Device: id(9), Network: 7, Attrs: []uint64{1, 4, 5}, Now: t0.Add(3 * time.Hour)})
	if r.Total != 1 || r.AttrCounts[0] != 1 || len(r.Siblings) != 0 {
		t.Fatalf("after forget: %+v", r)
	}

	// Expiry.
	if b, _ := s2.Expire(t0.Add(181 * 24 * time.Hour)); b != 1 {
		t.Fatalf("expired %d browsers", b)
	}
	if b, c := s2.Counts(); b != 0 || c != 0 {
		t.Fatalf("after expiry: %d browsers %d cookies", b, c)
	}
}

func TestEviction(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "s"), 0, 10)
	t0 := time.Unix(1_790_000_000, 0)
	for i := range 25 {
		s.Observe(Observation{Browser: id(byte(i)), Attrs: []uint64{uint64(i)}, Now: t0.Add(time.Duration(i) * time.Minute)})
	}
	if b, _ := s.Counts(); b > 10 {
		t.Fatalf("store grew to %d browsers", b)
	}
	// The newest one must have survived.
	r := s.Observe(Observation{Browser: id(24), Attrs: []uint64{24}, Now: t0.Add(time.Hour)})
	if !r.Seen {
		t.Fatal("newest browser was evicted")
	}
}

func TestSaveSkipsWhenClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	s := New(path, 0, 0)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := s.Load(); err != nil {
		t.Fatal(err) // missing file loads as empty
	}
}
