package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// fakeDBIP serves editions by month; months missing from the map are 404s,
// like editions DB-IP has not published yet.
type fakeDBIP struct {
	mu       sync.Mutex
	files    map[string][]byte // "city-2026-10" -> gzipped body
	requests []string
}

func (f *fakeDBIP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.Path)
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/dbip-"), ".mmdb.gz")
	name = strings.Replace(name, "-lite-", "-", 1)
	body, ok := f.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(body)
}

func (f *fakeDBIP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func cityDB(city string) []byte {
	return buildDB([]entry{{netip.MustParsePrefix("198.51.100.0/24"), map[string]any{
		"city":    map[string]any{"names": map[string]any{"en": city}},
		"country": map[string]any{"iso_code": "FR", "names": map[string]any{"en": "France"}},
	}}})
}

func asnDB() []byte {
	return buildDB([]entry{{netip.MustParsePrefix("198.51.100.0/24"), map[string]any{
		"autonomous_system_number": uint32(64500), "autonomous_system_organization": "Example Net",
	}}})
}

func TestDownloaderLifecycle(t *testing.T) {
	now := time.Now().UTC()
	this := now.Format("2006-01")
	last := now.AddDate(0, 0, -now.Day()).Format("2006-01")
	fake := &fakeDBIP{files: map[string][]byte{
		"city-" + last: gzipped(cityDB("Lyon")),
		"asn-" + last:  gzipped(asnDB()),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	dir := t.TempDir()
	d := &DBIP{Dir: dir, Edition: "city", BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.7")

	// Early on the 1st: this month's edition is not out, nothing on disk,
	// so last month's is fetched.
	for _, kind := range []string{"city", "asn"} {
		if err := d.refresh(ctx, kind); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	loc, nw := d.Lookup(ip)
	if loc.City != "Lyon" || nw.ASN != 64500 {
		t.Fatalf("after first download: %+v %+v", loc, nw)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "dbip-city-lite.mmdb.edition")); string(b) != last {
		t.Fatalf("edition marker = %q, want %q", b, last)
	}

	// Still unpublished: keep what we have, no error.
	before := fake.count()
	if err := d.refresh(ctx, "city"); err != nil {
		t.Fatalf("unpublished edition with data on disk: %v", err)
	}
	if fake.count() != before+1 {
		t.Fatalf("expected one probe for this month, got %d", fake.count()-before)
	}

	// A corrupt edition is rejected and the old database stays in place.
	fake.mu.Lock()
	fake.files["city-"+this] = gzipped([]byte("not a database"))
	fake.mu.Unlock()
	if err := d.refresh(ctx, "city"); err == nil {
		t.Fatal("corrupt download accepted")
	}
	if loc, _ := d.Lookup(ip); loc.City != "Lyon" {
		t.Fatalf("old database lost after a bad download: %+v", loc)
	}

	// The new edition appears and replaces the old one.
	fake.mu.Lock()
	fake.files["city-"+this] = gzipped(cityDB("Paris"))
	fake.mu.Unlock()
	if err := d.refresh(ctx, "city"); err != nil {
		t.Fatal(err)
	}
	if loc, _ := d.Lookup(ip); loc.City != "Paris" {
		t.Fatalf("new edition not loaded: %+v", loc)
	}

	// Up to date: no request at all.
	before = fake.count()
	if err := d.refresh(ctx, "city"); err != nil || fake.count() != before {
		t.Fatalf("refresh of a current edition: err=%v requests=%d", err, fake.count()-before)
	}

	// A restart loads from disk without downloading.
	d2 := &DBIP{Dir: dir, Edition: "city", BaseURL: srv.URL, Client: srv.Client()}
	d2.Load()
	if loc, _ := d2.Lookup(ip); loc.City != "Paris" {
		t.Fatalf("after restart: %+v", loc)
	}
	if _, err := os.Stat(filepath.Join(dir, "dbip-city-lite.mmdb")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".download-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestDownloaderNothingPublished(t *testing.T) {
	srv := httptest.NewServer(&fakeDBIP{files: map[string][]byte{}})
	defer srv.Close()
	d := &DBIP{Dir: t.TempDir(), Edition: "city", BaseURL: srv.URL, Client: srv.Client()}
	if err := d.refresh(context.Background(), "city"); err == nil {
		t.Fatal("expected an error when no edition can be found")
	}
	if loc, nw := d.Lookup(netip.MustParseAddr("198.51.100.7")); loc != (Location{}) || nw != (Network{}) {
		t.Fatal("lookups without a database must return zero values")
	}
}
