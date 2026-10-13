package netfp

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func frame(typ, flags byte, stream uint32, payload []byte) []byte {
	var b bytes.Buffer
	n := len(payload)
	b.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags})
	_ = binary.Write(&b, binary.BigEndian, stream)
	b.Write(payload)
	return b.Bytes()
}

func settings(pairs ...uint32) []byte {
	var b bytes.Buffer
	for i := 0; i+1 < len(pairs); i += 2 {
		_ = binary.Write(&b, binary.BigEndian, uint16(pairs[i]))
		_ = binary.Write(&b, binary.BigEndian, pairs[i+1])
	}
	return b.Bytes()
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// chromeLike builds the opening of a Chromium HTTP/2 connection.
func chromeLike() []byte {
	var b bytes.Buffer
	b.WriteString(h2Preface)
	b.Write(frame(0x4, 0, 0, settings(1, 65536, 2, 0, 4, 6291456, 6, 262144)))
	b.Write(frame(0x8, 0, 0, u32(15663105)))
	// HEADERS with PRIORITY flag: exclusive, depends on 0, weight 256.
	block := []byte{0x80, 0, 0, 0, 255}
	block = append(block, 0x82)       // :method GET (indexed 2)
	block = append(block, 0x41, 0x8b) // :authority, literal with indexing, Huffman value of 11 bytes
	block = append(block, bytes.Repeat([]byte{0xaa}, 11)...)
	block = append(block, 0x87)       // :scheme https
	block = append(block, 0x84)       // :path /
	block = append(block, 0x40, 0x0a) // regular header with a new name...
	block = append(block, []byte("user-agent")...)
	b.Write(frame(0x1, 0x4|0x1|0x20, 1, block))
	return b.Bytes()
}

func TestH2Chrome(t *testing.T) {
	f, err := ParseH2(chromeLike())
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Fatal("expected a complete fingerprint")
	}
	if got := f.Akamai(); got != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Fatalf("akamai = %s", got)
	}
	if f.HeadersPriority == nil || f.HeadersPriority.Weight != 256 || !f.HeadersPriority.Exclusive {
		t.Fatalf("headers priority = %+v", f.HeadersPriority)
	}
	if f.Family() != "chromium" {
		t.Fatalf("family = %s", f.Family())
	}
}

func TestH2PriorityFramesAndLiterals(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(h2Preface)
	b.Write(frame(0x4, 0, 0, settings(1, 65536, 4, 131072, 5, 16384)))
	b.Write(frame(0x4, 0x1, 0, nil)) // ACK must be ignored
	b.Write(frame(0x8, 0, 0, u32(12517377)))
	b.Write(frame(0x2, 0, 3, append(u32(0), 200)))
	b.Write(frame(0x2, 0, 5, append(u32(0), 100)))
	// :method GET, then :path as a literal without indexing (index 4, raw value),
	// :authority never-indexed with a raw value, :scheme https.
	block := []byte{0x82, 0x04, 0x01, '/', 0x11, 0x03, 'a', '.', 'b', 0x87, 0x90}
	b.Write(frame(0x1, 0x4, 1, block))
	f, err := ParseH2(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Akamai(); got != "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101|m,p,a,s" {
		t.Fatalf("akamai = %s", got)
	}
	if f.Family() != "firefox" {
		t.Fatalf("family = %s", f.Family())
	}
}

func TestH2Truncated(t *testing.T) {
	full := chromeLike()
	f, err := ParseH2(full[:len(full)-20])
	if err != nil {
		t.Fatal(err)
	}
	if f.Complete || len(f.Settings) != 4 {
		t.Fatalf("partial fingerprint = %+v", f)
	}
	if _, err := ParseH2([]byte("GET / HTTP/1.1\r\n")); err != ErrNotH2 {
		t.Fatalf("err = %v", err)
	}
}

func TestHeaderOrderH1(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"
	got := HeaderOrderH1([]byte(req))
	if !slices.Equal(got, []string{"host", "user-agent", "accept"}) {
		t.Fatalf("order = %v", got)
	}
	if HeaderOrderH1([]byte("GET / HTTP/1.1\r\nHost: x\r\n")) != nil {
		t.Fatal("incomplete head should give nil")
	}
}

func TestH2FamilyLibraries(t *testing.T) {
	cases := map[string]*H2Fingerprint{
		"nghttp2": {Settings: []H2Setting{{3, 100}, {4, 10485760}, {2, 0}}, WindowUpdate: 1048510465, PseudoHeaders: []string{":method", ":scheme", ":authority", ":path"}},
		"apple":   {Settings: []H2Setting{{2, 0}, {3, 100}, {4, 2097152}, {8, 1}, {9, 1}}, WindowUpdate: 10420225, PseudoHeaders: []string{":method", ":scheme", ":authority", ":path"}},
		"go":      {Settings: []H2Setting{{2, 0}, {4, 4194304}}, WindowUpdate: 1073741824, PseudoHeaders: []string{":authority", ":method", ":path", ":scheme"}},
	}
	for want, f := range cases {
		if got := f.Family(); got != want {
			t.Errorf("%s: got %s", want, got)
		}
	}
}
