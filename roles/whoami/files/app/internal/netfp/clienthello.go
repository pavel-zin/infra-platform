package netfp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ClientHello holds the fields of a TLS ClientHello that fingerprinting
// methods look at. Slices keep the order and the GREASE values exactly as
// the client sent them; the fingerprint functions filter GREASE themselves.
type ClientHello struct {
	LegacyVersion       uint16
	CipherSuites        []uint16
	Extensions          []uint16
	ServerName          string
	SupportedGroups     []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	ALPN                []string
	SupportedVersions   []uint16
	KeyShareGroups      []uint16
	CertCompression     []uint16
	PSKModes            []uint8
	RecordSizeLimit     int // -1 when the extension is absent
	SessionIDLength     int
}

// Extension code points referenced by name.
const (
	extServerName          = 0x0000
	extStatusRequest       = 0x0005
	extSupportedGroups     = 0x000a
	extPointFormats        = 0x000b
	extSignatureAlgorithms = 0x000d
	extALPN                = 0x0010
	extSCT                 = 0x0012
	extPadding             = 0x0015
	extEncryptThenMAC      = 0x0016
	extExtendedMasterSec   = 0x0017
	extCompressCert        = 0x001b
	extRecordSizeLimit     = 0x001c
	extDelegatedCreds      = 0x0022
	extSessionTicket       = 0x0023
	extPreSharedKey        = 0x0029
	extSupportedVersions   = 0x002b
	extPSKModes            = 0x002d
	extPostHandshakeAuth   = 0x0031
	extKeyShare            = 0x0033
	extALPSOld             = 0x4469
	extALPSNew             = 0x44cd
	extECH                 = 0xfe0d
	extRenegotiationInfo   = 0xff01
)

// IsGREASE reports whether v is one of the reserved GREASE values
// (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

var errShort = errors.New("tls: truncated ClientHello")

// ParseClientHelloRecords parses the first handshake message from the raw
// bytes a client sent at the start of a TLS connection. The ClientHello may be
// split across several TLS records (large post-quantum key shares make this
// common), so record fragments are reassembled first.
func ParseClientHelloRecords(b []byte) (*ClientHello, error) {
	var hs []byte
	for {
		if len(hs) >= 4 {
			n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+n {
				if hs[0] != 1 {
					return nil, fmt.Errorf("tls: first handshake message is type %d, not ClientHello", hs[0])
				}
				return ParseClientHello(hs[4 : 4+n])
			}
		}
		if len(b) < 5 {
			return nil, errShort
		}
		if b[0] != 22 {
			return nil, fmt.Errorf("tls: record type %d is not a handshake", b[0])
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			return nil, errShort
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
	}
}

// reader is a minimal big-endian cursor that records the first error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errShort
		r.b = nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (r *reader) u16() uint16 {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

func (r *reader) vec8() []byte  { return r.take(int(r.u8())) }
func (r *reader) vec16() []byte { return r.take(int(r.u16())) }

func u16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}

// ParseClientHello parses the body of a ClientHello handshake message.
func ParseClientHello(msg []byte) (*ClientHello, error) {
	r := &reader{b: msg}
	h := &ClientHello{RecordSizeLimit: -1}
	h.LegacyVersion = r.u16()
	r.take(32) // random
	h.SessionIDLength = len(r.vec8())
	h.CipherSuites = u16s(r.vec16())
	r.vec8() // compression methods
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) == 0 {
		return h, nil // no extensions (pre-TLS 1.2 style hello)
	}
	exts := &reader{b: r.vec16()}
	if r.err != nil {
		return nil, r.err
	}
	for len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.vec16()
		if exts.err != nil {
			return nil, exts.err
		}
		h.Extensions = append(h.Extensions, typ)
		if err := h.parseExtension(typ, data); err != nil {
			return nil, fmt.Errorf("tls: extension %#04x: %w", typ, err)
		}
	}
	return h, nil
}

func (h *ClientHello) parseExtension(typ uint16, data []byte) error {
	r := &reader{b: data}
	switch typ {
	case extServerName:
		list := &reader{b: r.vec16()}
		for len(list.b) > 0 && list.err == nil {
			kind := list.u8()
			name := list.vec16()
			if kind == 0 && h.ServerName == "" {
				h.ServerName = string(name)
			}
		}
		return list.err
	case extSupportedGroups:
		h.SupportedGroups = u16s(r.vec16())
	case extPointFormats:
		h.PointFormats = append([]uint8(nil), r.vec8()...)
	case extSignatureAlgorithms:
		h.SignatureAlgorithms = u16s(r.vec16())
	case extALPN:
		list := &reader{b: r.vec16()}
		for len(list.b) > 0 && list.err == nil {
			h.ALPN = append(h.ALPN, string(list.vec8()))
		}
		return list.err
	case extSupportedVersions:
		h.SupportedVersions = u16s(r.vec8())
	case extKeyShare:
		list := &reader{b: r.vec16()}
		for len(list.b) > 0 && list.err == nil {
			group := list.u16()
			list.vec16() // key exchange bytes
			h.KeyShareGroups = append(h.KeyShareGroups, group)
		}
		return list.err
	case extCompressCert:
		h.CertCompression = u16s(r.vec8())
	case extPSKModes:
		h.PSKModes = append([]uint8(nil), r.vec8()...)
	case extRecordSizeLimit:
		h.RecordSizeLimit = int(r.u16())
	default:
		return nil
	}
	return r.err
}

func (h *ClientHello) has(ext uint16) bool { return slices.Contains(h.Extensions, ext) }

// HasGREASE reports whether the client sent GREASE values anywhere in the
// cipher or extension lists (Chromium, Safari) or not (Firefox, OpenSSL, Go).
func (h *ClientHello) HasGREASE() bool {
	return slices.ContainsFunc(h.CipherSuites, IsGREASE) || slices.ContainsFunc(h.Extensions, IsGREASE)
}

func withoutGREASE(v []uint16) []uint16 {
	return slices.DeleteFunc(slices.Clone(v), IsGREASE)
}

func joinDec[T uint8 | uint16](v []T) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(int(x))
	}
	return strings.Join(parts, "-")
}

func joinHex(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

// JA3 returns the JA3 string and its MD5 hash (Salesforce, 2017):
// version,ciphers,extensions,groups,point formats with GREASE removed.
// Chromium has shuffled its extension order on every connection since
// version 110, so JA3 is no longer stable for Chromium browsers; JA4 sorts the
// lists to stay stable.
func (h *ClientHello) JA3() (raw, hash string) {
	pf := make([]uint16, len(h.PointFormats))
	for i, p := range h.PointFormats {
		pf[i] = uint16(p)
	}
	raw = strings.Join([]string{
		strconv.Itoa(int(h.LegacyVersion)),
		joinDec(withoutGREASE(h.CipherSuites)),
		joinDec(withoutGREASE(h.Extensions)),
		joinDec(withoutGREASE(h.SupportedGroups)),
		joinDec(pf),
	}, ",")
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// Version is the highest TLS version the client offered.
func (h *ClientHello) Version() uint16 {
	if versions := withoutGREASE(h.SupportedVersions); len(versions) > 0 {
		return slices.Max(versions)
	}
	return h.LegacyVersion
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	first, last := v[0], v[len(v)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	x := hex.EncodeToString([]byte(v))
	return string([]byte{x[0], x[len(x)-1]})
}

func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// JA4 returns the JA4 TLS client fingerprint (FoxIO, BSD 3-Clause) and its
// raw, unhashed form (ja4_r).
func (h *ClientHello) JA4() (fp, raw string) {
	sni := "i"
	if h.has(extServerName) {
		sni = "d"
	}
	ciphers := withoutGREASE(h.CipherSuites)
	exts := withoutGREASE(h.Extensions)
	a := "t" + ja4Version(h.Version()) + sni + twoDigits(len(ciphers)) + twoDigits(len(exts)) + ja4ALPN(h.ALPN)

	sortedCiphers := slices.Clone(ciphers)
	slices.Sort(sortedCiphers)
	cipherList := joinHex(sortedCiphers)

	sortedExts := slices.DeleteFunc(slices.Clone(exts), func(e uint16) bool {
		return e == extServerName || e == extALPN
	})
	slices.Sort(sortedExts)
	extList := joinHex(sortedExts)
	if sigs := withoutGREASE(h.SignatureAlgorithms); len(sigs) > 0 {
		extList += "_" + joinHex(sigs)
	}

	b, c := "000000000000", "000000000000"
	if len(sortedCiphers) > 0 {
		b = sha12(cipherList)
	}
	if len(sortedExts) > 0 {
		c = sha12(extList)
	}
	return a + "_" + b + "_" + c, a + "_" + cipherList + "_" + extList
}

// knownCipherLists maps the JA4 cipher hash (section b) of a few TLS stacks
// to a family. Chromium's list no longer identifies it: Firefox 155 offers the
// identical set, so browser families are told apart by extensions first.
var knownCipherLists = map[string]string{
	"a09f3c656075": "apple",
	"9dc949149365": "go",
	"e33ad33b3d25": "go",
	"cbb2034c60b8": "go",
	"f57a46bbacb6": "go",
}

// Family guesses which TLS library produced the hello. It is a heuristic and
// is presented as one.
func (h *ClientHello) Family() string {
	grease := h.HasGREASE()
	switch {
	case h.has(extRecordSizeLimit) && h.has(extDelegatedCreds):
		return "firefox" // NSS: record_size_limit and delegated_credentials
	case h.has(extALPSOld) || h.has(extALPSNew):
		return "chromium" // BoringSSL with Chrome's ALPS extension
	}
	sorted := withoutGREASE(h.CipherSuites)
	slices.Sort(sorted)
	if f, ok := knownCipherLists[sha12(joinHex(sorted))]; ok && (f != "apple" || grease) {
		return f
	}
	switch {
	case grease && slices.Contains(h.CertCompression, 1):
		return "apple" // GREASE plus zlib certificate compression
	case grease:
		return "chromium"
	case h.has(extEncryptThenMAC):
		return "openssl" // curl, wget, Python, Node.js, ...
	}
	return "unknown"
}

// FamilyName is the human-readable form of a Family value.
func FamilyName(f string) string {
	switch f {
	case "chromium":
		return "Chromium (BoringSSL)"
	case "firefox":
		return "Firefox (NSS)"
	case "apple":
		return "Safari / Apple network stack"
	case "openssl":
		return "OpenSSL-based tool (curl, Python, Node.js…)"
	case "go":
		return "Go program"
	case "nghttp2":
		return "nghttp2-based tool (curl…)"
	}
	return "Unknown"
}

// GroupName returns a readable name for a TLS supported-group code point.
func GroupName(g uint16) string {
	switch g {
	case 0x0017:
		return "P-256"
	case 0x0018:
		return "P-384"
	case 0x0019:
		return "P-521"
	case 0x001d:
		return "X25519"
	case 0x001e:
		return "X448"
	case 0x0100:
		return "ffdhe2048"
	case 0x0101:
		return "ffdhe3072"
	case 0x11ec:
		return "X25519MLKEM768"
	case 0x11eb:
		return "SecP256r1MLKEM768"
	case 0x11ed:
		return "SecP384r1MLKEM1024"
	case 0x6399:
		return "X25519Kyber768Draft00"
	}
	if IsGREASE(g) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", g)
}
