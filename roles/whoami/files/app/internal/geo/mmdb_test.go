package geo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// --- a tiny MaxMind DB writer, just enough to exercise the reader ---

func encodeCtrl(typ, size int) []byte {
	var out []byte
	ext := typ > 7
	t := typ
	if ext {
		t = 0
	}
	switch {
	case size < 29:
		out = []byte{byte(t<<5 | size)}
	case size < 285:
		out = []byte{byte(t<<5 | 29), byte(size - 29)}
	default:
		s := size - 285
		out = []byte{byte(t<<5 | 30), byte(s >> 8), byte(s)}
	}
	if ext {
		out = append(out[:1], append([]byte{byte(typ - 7)}, out[1:]...)...)
	}
	return out
}

func encodeValue(v any) []byte {
	switch x := v.(type) {
	case string:
		return append(encodeCtrl(2, len(x)), x...)
	case float64:
		b := encodeCtrl(3, 8)
		return binary.BigEndian.AppendUint64(b, math.Float64bits(x))
	case uint32:
		b := binary.BigEndian.AppendUint32(nil, x)
		b = bytes.TrimLeft(b, "\x00")
		return append(encodeCtrl(6, len(b)), b...)
	case uint64:
		b := binary.BigEndian.AppendUint64(nil, x)
		b = bytes.TrimLeft(b, "\x00")
		return append(encodeCtrl(9, len(b)), b...)
	case bool:
		n := 0
		if x {
			n = 1
		}
		return encodeCtrl(14, n)
	case []any:
		b := encodeCtrl(11, len(x))
		for _, e := range x {
			b = append(b, encodeValue(e)...)
		}
		return b
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b := encodeCtrl(7, len(x))
		for _, k := range keys {
			b = append(b, encodeValue(k)...)
			b = append(b, encodeValue(x[k])...)
		}
		return b
	case pointer:
		return []byte{byte(1<<5 | 0<<3 | (int(x)>>8)&0x7), byte(x)}
	}
	panic("unsupported type")
}

type pointer int

type entry struct {
	prefix netip.Prefix
	value  any
}

// buildDB writes an IPv6 database with 24-bit records.
func buildDB(entries []entry) []byte {
	type node struct{ rec [2]int64 } // >=0 node index, -1 empty, <=-2 data #(-rec-2)
	nodes := []node{{rec: [2]int64{-1, -1}}}
	var data []byte
	offsets := []int{}
	for i, e := range entries {
		offsets = append(offsets, len(data))
		data = append(data, encodeValue(e.value)...)
		a := e.prefix.Addr()
		bits := e.prefix.Bits()
		if a.Is4() {
			a = netip.AddrFrom16(a.As16()) // ::ffff:a.b.c.d -> rewrite to ::a.b.c.d below
			b := a.As16()
			b[10], b[11] = 0, 0
			a = netip.AddrFrom16(b)
			bits += 96
		}
		addr := a.As16()
		cur := 0
		for d := 0; d < bits; d++ {
			bit := (addr[d/8] >> (7 - uint(d%8))) & 1
			if d == bits-1 {
				nodes[cur].rec[bit] = int64(-2 - i)
				break
			}
			next := nodes[cur].rec[bit]
			if next < 0 {
				nodes = append(nodes, node{rec: [2]int64{-1, -1}})
				next = int64(len(nodes) - 1)
				nodes[cur].rec[bit] = next
			}
			cur = int(next)
		}
	}
	n := len(nodes)
	var out []byte
	for _, nd := range nodes {
		for _, r := range nd.rec {
			var v int
			switch {
			case r >= 0:
				v = int(r)
			case r == -1:
				v = n
			default:
				v = n + 16 + offsets[-r-2]
			}
			out = append(out, byte(v>>16), byte(v>>8), byte(v))
		}
	}
	out = append(out, make([]byte, 16)...)
	out = append(out, data...)
	out = append(out, metadataMarker...)
	out = append(out, encodeValue(map[string]any{
		"node_count":                  uint32(n),
		"record_size":                 uint32(24),
		"ip_version":                  uint32(6),
		"database_type":               "Test-City",
		"build_epoch":                 uint64(1790818881),
		"binary_format_major_version": uint32(2),
		"languages":                   []any{"en"},
	})...)
	return out
}

func TestReaderSynthetic(t *testing.T) {
	db := buildDB([]entry{
		{netip.MustParsePrefix("81.250.0.0/16"), map[string]any{
			"country":      map[string]any{"iso_code": "FR", "names": map[string]any{"en": "France"}, "is_in_european_union": true},
			"city":         map[string]any{"names": map[string]any{"en": "Paris"}},
			"location":     map[string]any{"latitude": 48.85, "longitude": 2.35},
			"subdivisions": []any{map[string]any{"names": map[string]any{"en": "Île-de-France"}}},
		}},
		{netip.MustParsePrefix("2001:db8::/32"), map[string]any{"autonomous_system_number": uint32(64500), "autonomous_system_organization": "Example Net"}},
	})
	r, err := FromBytes(db)
	if err != nil {
		t.Fatal(err)
	}
	if r.Metadata.DatabaseType != "Test-City" || r.Metadata.BuildEpoch != 1790818881 {
		t.Fatalf("metadata = %+v", r.Metadata)
	}
	rec, ok, err := r.Lookup(netip.MustParseAddr("81.250.7.1"))
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	loc := locationFrom(rec)
	want := Location{City: "Paris", Region: "Île-de-France", Country: "France", CountryCode: "FR", Latitude: 48.85, Longitude: 2.35, EU: true}
	if loc != want {
		t.Fatalf("location = %+v", loc)
	}
	rec, ok, _ = r.Lookup(netip.MustParseAddr("2001:db8:1::5"))
	if m, _ := rec.(map[string]any); !ok || asUint(m["autonomous_system_number"]) != 64500 {
		t.Fatalf("ipv6 record = %v", rec)
	}
	for _, miss := range []string{"81.251.0.1", "8.8.8.8", "2001:db9::1"} {
		if _, ok, err := r.Lookup(netip.MustParseAddr(miss)); ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v", miss, ok, err)
		}
	}
}

func TestDecoderPointerAndSizes(t *testing.T) {
	long := string(bytes.Repeat([]byte("x"), 300))
	data := encodeValue(long) // offset 0
	ptrAt := len(data)        // a map whose value points back to the string
	data = append(data, encodeCtrl(7, 1)...)
	data = append(data, encodeValue("k")...)
	data = append(data, encodeValue(pointer(0))...)
	d := decoder{buf: data}
	v, _, err := d.decode(ptrAt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.(map[string]any)["k"] != long {
		t.Fatal("pointer did not resolve to the 300-byte string")
	}
	if _, _, err := (&decoder{buf: data[:10]}).decode(0, 0); err == nil {
		t.Fatal("truncated string should fail")
	}
}

// TestRealDatabases cross-checks against values produced by the reference
// Python reader for real DB-IP files. Set WHOAMI_TEST_DBIP to a directory
// with dbip-city-lite.mmdb, dbip-asn-lite.mmdb and expected.json to run it.
func TestRealDatabases(t *testing.T) {
	dir := os.Getenv("WHOAMI_TEST_DBIP")
	if dir == "" {
		t.Skip("WHOAMI_TEST_DBIP not set")
	}
	var expected map[string]struct {
		City, Country string
		ASN           uint64
		Org           string
	}
	b, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	db := &DBIP{Dir: dir, Edition: "city"}
	db.Load()
	for ip, want := range expected {
		loc, nw := db.Lookup(netip.MustParseAddr(ip))
		if loc.City != want.City || loc.CountryCode != want.Country || nw.ASN != want.ASN || nw.Org != want.Org {
			t.Errorf("%s: got %q %q AS%d %q, want %q %q AS%d %q", ip, loc.City, loc.CountryCode, nw.ASN, nw.Org, want.City, want.Country, want.ASN, want.Org)
		}
	}
	t.Logf("checked %d addresses", len(expected))
}

func TestHosting(t *testing.T) {
	cases := map[Network]bool{
		{ASN: 3215, Org: "Orange S.A."}:                  false,
		{ASN: 31898, Org: "Oracle Corporation"}:          true,
		{ASN: 99999, Org: "Example Hosting Ltd"}:         true,
		{ASN: 16591, Org: "Google Fiber Inc."}:           false,
		{ASN: 7922, Org: "Comcast Cable Communications"}: false,
	}
	for n, want := range cases {
		if got := IsHosting(n); got != want {
			t.Errorf("IsHosting(%v) = %v", n, got)
		}
	}
}
