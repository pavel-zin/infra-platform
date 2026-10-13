package netfp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// HTTP/2 fingerprinting (Akamai, "Passive Fingerprinting of HTTP/2 Clients",
// Black Hat EU 2017): every client implementation opens a connection with its
// own SETTINGS values and order, connection window increment, PRIORITY frames
// and pseudo-header order. Anti-bot services compare this with the claimed
// User-Agent.

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// H2Setting is one SETTINGS parameter as sent by the client.
type H2Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// H2Priority is a PRIORITY frame (or the priority block of a HEADERS frame).
type H2Priority struct {
	StreamID  uint32 `json:"stream"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"dependsOn"`
	Weight    int    `json:"weight"` // 1..256, i.e. the wire value plus one
}

func (p H2Priority) String() string {
	e := 0
	if p.Exclusive {
		e = 1
	}
	return fmt.Sprintf("%d:%d:%d:%d", p.StreamID, e, p.DependsOn, p.Weight)
}

// H2Fingerprint is what a client revealed before and in its first request.
type H2Fingerprint struct {
	Settings        []H2Setting  `json:"settings"`
	WindowUpdate    uint32       `json:"windowUpdate"`
	Priorities      []H2Priority `json:"priorities"`
	PseudoHeaders   []string     `json:"pseudoHeaders"`
	HeadersPriority *H2Priority  `json:"headersPriority,omitempty"`
	Complete        bool         `json:"complete"` // the first HEADERS frame was seen
}

// Akamai renders the fingerprint in Akamai's format:
// SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER.
func (f *H2Fingerprint) Akamai() string {
	settings := make([]string, len(f.Settings))
	for i, s := range f.Settings {
		settings[i] = fmt.Sprintf("%d:%d", s.ID, s.Value)
	}
	window := "00"
	if f.WindowUpdate != 0 {
		window = fmt.Sprint(f.WindowUpdate)
	}
	prio := "0"
	if len(f.Priorities) > 0 {
		parts := make([]string, len(f.Priorities))
		for i, p := range f.Priorities {
			parts[i] = p.String()
		}
		prio = strings.Join(parts, ",")
	}
	pseudo := make([]string, len(f.PseudoHeaders))
	for i, h := range f.PseudoHeaders {
		pseudo[i] = h[1:2]
	}
	return strings.Join(settings, ";") + "|" + window + "|" + prio + "|" + strings.Join(pseudo, ",")
}

// Family guesses the client implementation from the pseudo-header order and
// connection window, which differ between the major HTTP/2 stacks.
func (f *H2Fingerprint) Family() string {
	order := strings.Join(f.PseudoHeaders, ",")
	first := uint16(0)
	if len(f.Settings) > 0 {
		first = f.Settings[0].ID
	}
	switch {
	case order == ":authority,:method,:path,:scheme":
		return "go"
	// nghttp2 (curl and friends) leads with MAX_CONCURRENT_STREAMS and opens
	// the connection window to about 1 GiB; browsers use a few MiB.
	case first == 3 && f.WindowUpdate >= 1<<29:
		return "nghttp2"
	case order == ":method,:authority,:scheme,:path":
		return "chromium"
	case order == ":method,:path,:authority,:scheme":
		return "firefox"
	case strings.HasPrefix(order, ":method,:scheme,") && first == 2:
		return "apple" // Safari leads with ENABLE_PUSH=0
	case order == ":method,:path,:scheme,:authority":
		return "nghttp2"
	}
	return "unknown"
}

// SettingName returns the RFC name of a SETTINGS identifier.
func SettingName(id uint16) string {
	switch id {
	case 1:
		return "HEADER_TABLE_SIZE"
	case 2:
		return "ENABLE_PUSH"
	case 3:
		return "MAX_CONCURRENT_STREAMS"
	case 4:
		return "INITIAL_WINDOW_SIZE"
	case 5:
		return "MAX_FRAME_SIZE"
	case 6:
		return "MAX_HEADER_LIST_SIZE"
	case 8:
		return "ENABLE_CONNECT_PROTOCOL"
	case 9:
		return "NO_RFC7540_PRIORITIES"
	}
	return fmt.Sprintf("0x%x", id)
}

// ErrNotH2 is returned when the bytes do not start with the HTTP/2 preface.
var ErrNotH2 = errors.New("h2: no client connection preface")

// ParseH2 reads the client connection preface and the frames that follow it,
// up to and including the first HEADERS frame. Truncated input yields a
// partial fingerprint with Complete=false.
func ParseH2(b []byte) (*H2Fingerprint, error) {
	if !bytes.HasPrefix(b, []byte(h2Preface)) {
		return nil, ErrNotH2
	}
	b = b[len(h2Preface):]
	f := &H2Fingerprint{}
	seenSettings := false
	for len(b) >= 9 {
		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		typ, flags := b[3], b[4]
		stream := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff
		if len(b) < 9+length {
			break
		}
		payload := b[9 : 9+length]
		b = b[9+length:]
		switch typ {
		case 0x4: // SETTINGS
			if flags&0x1 != 0 || seenSettings {
				continue // ACK, or a later SETTINGS frame
			}
			seenSettings = true
			for i := 0; i+6 <= len(payload); i += 6 {
				f.Settings = append(f.Settings, H2Setting{
					ID:    binary.BigEndian.Uint16(payload[i:]),
					Value: binary.BigEndian.Uint32(payload[i+2:]),
				})
			}
		case 0x8: // WINDOW_UPDATE
			if stream == 0 && f.WindowUpdate == 0 && len(payload) >= 4 {
				f.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		case 0x2: // PRIORITY
			if len(payload) >= 5 {
				f.Priorities = append(f.Priorities, parsePriority(stream, payload))
			}
		case 0x1: // HEADERS
			block := payload
			if flags&0x8 != 0 { // PADDED
				if len(block) < 1 {
					return f, nil
				}
				pad := int(block[0])
				block = block[1:]
				if pad > len(block) {
					return f, nil
				}
				block = block[:len(block)-pad]
			}
			if flags&0x20 != 0 { // PRIORITY
				if len(block) < 5 {
					return f, nil
				}
				p := parsePriority(stream, block)
				f.HeadersPriority = &p
				block = block[5:]
			}
			f.PseudoHeaders = pseudoHeaderOrder(block)
			f.Complete = true
			return f, nil
		}
	}
	return f, nil
}

func parsePriority(stream uint32, p []byte) H2Priority {
	dep := binary.BigEndian.Uint32(p)
	return H2Priority{
		StreamID:  stream,
		Exclusive: dep&0x80000000 != 0,
		DependsOn: dep & 0x7fffffff,
		Weight:    int(p[4]) + 1,
	}
}

// hpackStatic holds the names of the static table entries that are
// pseudo-headers (RFC 7541, Appendix A). Every other index is a regular
// header, which by RFC 9113 ends the pseudo-header section.
var hpackStatic = map[uint64]string{
	1: ":authority", 2: ":method", 3: ":method", 4: ":path", 5: ":path",
	6: ":scheme", 7: ":scheme", 8: ":status", 9: ":status", 10: ":status",
	11: ":status", 12: ":status", 13: ":status", 14: ":status",
}

// hpackInt decodes an HPACK integer with an n-bit prefix.
func hpackInt(b []byte, n uint) (v uint64, size int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	max := uint64(1)<<n - 1
	v = uint64(b[0]) & max
	if v < max {
		return v, 1, true
	}
	var shift uint
	for i := 1; i < len(b) && i < 10; i++ {
		v += uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

// hpackString returns the raw (possibly Huffman-coded) bytes of a string
// literal and the total encoded size.
func hpackString(b []byte) (s []byte, huffman bool, size int, ok bool) {
	if len(b) == 0 {
		return nil, false, 0, false
	}
	n, k, ok := hpackInt(b, 7)
	if !ok || uint64(len(b)-k) < n {
		return nil, false, 0, false
	}
	return b[k : k+int(n)], b[0]&0x80 != 0, k + int(n), true
}

// pseudoHeaderOrder walks the start of the first header block. Pseudo-header
// names always come from the static table on a fresh connection, so neither
// Huffman decoding nor a dynamic table is needed to recover their order.
func pseudoHeaderOrder(b []byte) []string {
	var order []string
	for len(b) > 0 {
		c := b[0]
		var (
			index  uint64
			n      int
			ok     bool
			hasVal bool
		)
		switch {
		case c&0x80 != 0: // indexed header field
			index, n, ok = hpackInt(b, 7)
		case c&0xc0 == 0x40: // literal with incremental indexing
			index, n, ok = hpackInt(b, 6)
			hasVal = true
		case c&0xe0 == 0x20: // dynamic table size update
			_, n, ok = hpackInt(b, 5)
			if !ok {
				return order
			}
			b = b[n:]
			continue
		default: // literal without indexing / never indexed
			index, n, ok = hpackInt(b, 4)
			hasVal = true
		}
		if !ok {
			return order
		}
		b = b[n:]
		var name string
		if index == 0 {
			raw, huff, size, ok := hpackString(b)
			if !ok || huff {
				return order
			}
			name = string(raw)
			b = b[size:]
		} else {
			name = hpackStatic[index]
		}
		if !strings.HasPrefix(name, ":") {
			return order
		}
		if hasVal {
			_, _, size, ok := hpackString(b)
			if !ok {
				return order
			}
			b = b[size:]
		}
		order = append(order, name)
	}
	return order
}

// HeaderOrderH1 returns the header names of the first HTTP/1.x request in b,
// in the order the client sent them (lower-cased).
func HeaderOrderH1(b []byte) []string {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return nil
	}
	lines := strings.Split(string(b[:end]), "\r\n")
	if len(lines) < 2 || !strings.Contains(lines[0], " HTTP/1.") {
		return nil
	}
	names := make([]string, 0, len(lines)-1)
	for _, l := range lines[1:] {
		if i := strings.IndexByte(l, ':'); i > 0 {
			names = append(names, strings.ToLower(strings.TrimSpace(l[:i])))
		}
	}
	return names
}
