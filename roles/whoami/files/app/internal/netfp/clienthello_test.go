package netfp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// testdata/clienthellos.json holds ClientHello records extracted from the
// pcaps in FoxIO's JA4 repository. Expected JA4/JA4_r values are FoxIO's own
// snapshot outputs; expected JA3 values come from Wireshark's implementation.
type helloVector struct {
	Name    string `json:"name"`
	Records string `json:"records"`
	JA3     string `json:"ja3"`
	JA3Full string `json:"ja3_full"`
	JA4     string `json:"ja4"`
	JA4R    string `json:"ja4_r"`
	Note    string `json:"note"`
}

func loadVectors(t *testing.T) []helloVector {
	t.Helper()
	b, err := os.ReadFile("testdata/clienthellos.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []helloVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFingerprintVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.Records)
			if err != nil {
				t.Fatal(err)
			}
			h, err := ParseClientHelloRecords(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ja3, ja3hash := h.JA3()
			if ja3 != v.JA3Full {
				t.Errorf("JA3 string\n got %s\nwant %s", ja3, v.JA3Full)
			}
			if ja3hash != v.JA3 {
				t.Errorf("JA3 hash got %s want %s", ja3hash, v.JA3)
			}
			ja4, ja4r := h.JA4()
			if ja4 != v.JA4 {
				t.Errorf("JA4 got %s want %s (%s)", ja4, v.JA4, v.Note)
			}
			if v.JA4R != "" && ja4r != v.JA4R {
				t.Errorf("JA4_r\n got %s\nwant %s", ja4r, v.JA4R)
			}
		})
	}
}

func TestJA4SpecExample(t *testing.T) {
	// The worked example from JA4.md.
	h := &ClientHello{
		LegacyVersion:       0x0303,
		CipherSuites:        []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:          []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		ALPN:                []string{"h2", "http/1.1"},
		RecordSizeLimit:     -1,
	}
	if got, _ := h.JA4(); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("JA4 = %s", got)
	}
}

func TestJA4ALPN(t *testing.T) {
	cases := map[string]string{
		"":                 "00",
		"h2":               "h2",
		"http/1.1":         "h1",
		"x":                "xx",
		"\xab":             "ab",
		"\xab\xcd":         "ad",
		"\x20\x61":         "21",
		"\x30\xab":         "3b",
		"\x61\x20":         "60",
		"\x30\x31\xab\xcd": "3d",
		"\x30\xab\xcd\x31": "01",
	}
	for in, want := range cases {
		var alpn []string
		if in != "" {
			alpn = []string{in}
		}
		if got := ja4ALPN(alpn); got != want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xaaaa, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("%#04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000, 0xabab} {
		if IsGREASE(v) {
			t.Errorf("%#04x should not be GREASE", v)
		}
	}
}

func TestFamilies(t *testing.T) {
	want := map[string]string{
		"browsers-x509.pcapng 172.27.7.31:54524": "chromium",
		"tls12.pcap 192.168.133.129:36372":       "firefox",
	}
	for _, v := range loadVectors(t) {
		f, ok := want[v.Name]
		if !ok {
			continue
		}
		raw, _ := hex.DecodeString(v.Records)
		h, err := ParseClientHelloRecords(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := h.Family(); got != f {
			t.Errorf("%s: family %s, want %s", v.Name, got, f)
		}
	}
}

func TestTruncatedHello(t *testing.T) {
	v := loadVectors(t)[0]
	raw, _ := hex.DecodeString(v.Records)
	for _, n := range []int{0, 3, 5, 40, len(raw) - 1} {
		if _, err := ParseClientHelloRecords(raw[:n]); err == nil {
			t.Errorf("parsing %d of %d bytes should fail", n, len(raw))
		}
	}
}

// Firefox 155 offers exactly Chromium's cipher list; its NSS extensions must
// still identify it (raw JA4 captured from Firefox 155 on Linux).
func TestFirefox155(t *testing.T) {
	h := &ClientHello{
		LegacyVersion:     0x0303,
		CipherSuites:      []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:        []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d},
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x0304, 0x0303},
		RecordSizeLimit:   16385,
	}
	if got := h.Family(); got != "firefox" {
		t.Fatalf("family = %s", got)
	}
	if ja4, _ := h.JA4(); ja4[:10] != "t13d1517h2" {
		t.Fatalf("ja4 = %s", ja4)
	}
}
