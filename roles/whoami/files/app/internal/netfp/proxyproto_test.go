package netfp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestProxyV1(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("PROXY TCP4 203.0.113.7 10.0.0.1 51234 443\r\n\x16\x03\x01"))
	src, ok, err := ReadProxyHeader(r)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if src.String() != "203.0.113.7:51234" {
		t.Fatalf("src = %s", src)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, []byte("\x16\x03\x01")) {
		t.Fatalf("payload after header = %q", rest)
	}
}

func TestProxyV1IPv6AndUnknown(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("PROXY TCP6 2001:db8::1 2001:db8::2 1000 443\r\n"))
	src, ok, err := ReadProxyHeader(r)
	if err != nil || !ok || src.String() != "[2001:db8::1]:1000" {
		t.Fatalf("src=%s ok=%v err=%v", src, ok, err)
	}
	r = bufio.NewReader(strings.NewReader("PROXY UNKNOWN\r\n"))
	if _, ok, err := ReadProxyHeader(r); err != nil || ok {
		t.Fatalf("UNKNOWN: ok=%v err=%v", ok, err)
	}
}

func TestProxyV2(t *testing.T) {
	var b bytes.Buffer
	b.Write(proxyV2Signature)
	b.WriteByte(0x21) // v2, PROXY
	b.WriteByte(0x11) // TCP over IPv4
	_ = binary.Write(&b, binary.BigEndian, uint16(12))
	b.Write([]byte{198, 51, 100, 9, 10, 0, 0, 1})
	_ = binary.Write(&b, binary.BigEndian, uint16(40000))
	_ = binary.Write(&b, binary.BigEndian, uint16(443))
	b.WriteString("hello")
	r := bufio.NewReader(&b)
	src, ok, err := ReadProxyHeader(r)
	if err != nil || !ok || src.String() != "198.51.100.9:40000" {
		t.Fatalf("src=%s ok=%v err=%v", src, ok, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "hello" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestProxyRejects(t *testing.T) {
	for _, in := range []string{
		"\x16\x03\x01\x02\x00", // TLS without header
		"PROXY TCP4 nonsense\r\n",
		"PROXY TCP4 1.2.3.4 5.6.7.8 99999 443\r\n",
		"PROXY " + strings.Repeat("A", 200),
	} {
		if _, _, err := ReadProxyHeader(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}
