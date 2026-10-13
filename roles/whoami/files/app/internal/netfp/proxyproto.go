package netfp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// The edge nginx terminates nothing for this service: it forwards the raw TCP
// stream (TLS included) and prepends a PROXY protocol header so the original
// client address survives the hop. nginx sends version 1; version 2 is
// accepted too so another proxy can be swapped in without code changes.

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ErrNoProxyHeader is returned when the stream does not start with a PROXY
// protocol header.
var ErrNoProxyHeader = errors.New("proxy protocol: header missing")

// ReadProxyHeader consumes a PROXY protocol header from r. It returns the
// original client address, or ok=false for LOCAL/UNKNOWN headers that carry no
// address (health checks).
func ReadProxyHeader(r *bufio.Reader) (src netip.AddrPort, ok bool, err error) {
	peek, err := r.Peek(5)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol: %w", err)
	}
	if string(peek) == "PROXY" {
		return readProxyV1(r)
	}
	if peek[0] == '\r' {
		sig, err := r.Peek(len(proxyV2Signature))
		if err == nil && bytes.Equal(sig, proxyV2Signature) {
			return readProxyV2(r)
		}
	}
	return netip.AddrPort{}, false, ErrNoProxyHeader
}

func readProxyV1(r *bufio.Reader) (netip.AddrPort, bool, error) {
	// The v1 header is at most 107 bytes including the trailing CRLF.
	line := make([]byte, 0, 108)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: %w", err)
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
		if len(line) >= 107 {
			return netip.AddrPort{}, false, errors.New("proxy protocol v1: header too long")
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return netip.AddrPort{}, false, errors.New("proxy protocol v1: missing CRLF")
	}
	fields := strings.Fields(string(line[:len(line)-2]))
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return netip.AddrPort{}, false, nil
	}
	if len(fields) != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: malformed header %q", line)
	}
	addr, err := netip.ParseAddr(fields[2])
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: source address: %w", err)
	}
	port, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v1: source port: %w", err)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true, nil
}

func readProxyV2(r *bufio.Reader) (netip.AddrPort, bool, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: %w", err)
	}
	verCmd, family := hdr[12], hdr[13]
	if verCmd>>4 != 2 {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: unsupported version %d", verCmd>>4)
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > 4096 {
		return netip.AddrPort{}, false, errors.New("proxy protocol v2: header too long")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: %w", err)
	}
	switch verCmd & 0x0f {
	case 0x0: // LOCAL: connection made by the proxy itself
		return netip.AddrPort{}, false, nil
	case 0x1: // PROXY
	default:
		return netip.AddrPort{}, false, fmt.Errorf("proxy protocol v2: unknown command %d", verCmd&0x0f)
	}
	switch family {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return netip.AddrPort{}, false, errors.New("proxy protocol v2: short IPv4 address block")
		}
		addr := netip.AddrFrom4([4]byte(body[0:4]))
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(body[8:10])), true, nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return netip.AddrPort{}, false, errors.New("proxy protocol v2: short IPv6 address block")
		}
		addr := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(body[32:34])), true, nil
	default:
		return netip.AddrPort{}, false, nil
	}
}
