package netfp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type observed struct {
	Remote   string
	Proto    string
	JA4      string
	Family   string
	Akamai   string
	H1Order  []string
	Hostname string
}

// startServer runs the Listener + http.Server pair the way main wires them.
func startServer(t *testing.T) (addr string) {
	t.Helper()
	certs, err := SelfSigned("whoami.test")
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListener(inner, &tls.Config{
		GetCertificate: certs.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	}, ListenerOptions{ProxyProtocol: true, HandshakeTimeout: 5 * time.Second})

	type ctxKey struct{}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Protocols: &protocols,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, ctxKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(ctxKey{}).(*Conn)
			hello, err := c.ClientHello()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			o := observed{Remote: r.RemoteAddr, Proto: r.Proto, Family: hello.Family(), H1Order: c.FirstRequestHeaderOrder(), Hostname: hello.ServerName}
			o.JA4, _ = hello.JA4()
			if f := c.H2(); f != nil {
				o.Akamai = f.Akamai()
			}
			_ = json.NewEncoder(w).Encode(o)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return inner.Addr().String()
}

func client(addr string, h2 bool) *http.Client {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, err := fmt.Fprintf(raw, "PROXY TCP4 192.0.2.44 10.0.0.1 40123 443\r\n"); err != nil {
				return nil, err
			}
			protos := []string{"http/1.1"}
			if h2 {
				protos = []string{"h2", "http/1.1"}
			}
			tc := tls.Client(raw, &tls.Config{ServerName: "whoami.test", InsecureSkipVerify: true, NextProtos: protos})
			return tc, tc.HandshakeContext(ctx)
		},
		ForceAttemptHTTP2: h2,
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func get(t *testing.T, c *http.Client) observed {
	t.Helper()
	resp, err := c.Get("https://whoami.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var o observed
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return o
}

func TestListenerHTTP2(t *testing.T) {
	addr := startServer(t)
	o := get(t, client(addr, true))
	if o.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %s", o.Proto)
	}
	if o.Remote != "192.0.2.44:40123" {
		t.Fatalf("remote = %s (PROXY header not applied)", o.Remote)
	}
	if !strings.HasPrefix(o.JA4, "t13d") || o.Hostname != "whoami.test" {
		t.Fatalf("ja4 = %s sni = %s", o.JA4, o.Hostname)
	}
	// Go's HTTP/2 client sends :authority first.
	if !strings.HasSuffix(o.Akamai, "|a,m,p,s") {
		t.Fatalf("akamai = %q", o.Akamai)
	}
	t.Logf("go client: %s / %s / %s", o.JA4, o.Akamai, o.Family)
}

func TestListenerHTTP1(t *testing.T) {
	addr := startServer(t)
	o := get(t, client(addr, false))
	if o.Proto != "HTTP/1.1" || o.Akamai != "" {
		t.Fatalf("proto = %s akamai = %q", o.Proto, o.Akamai)
	}
	if len(o.H1Order) == 0 || o.H1Order[0] != "host" {
		t.Fatalf("h1 header order = %v", o.H1Order)
	}
}

func TestListenerRejectsMissingProxyHeader(t *testing.T) {
	addr := startServer(t)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake without PROXY header should fail")
	}
}
