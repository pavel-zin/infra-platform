package netfp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Listener accepts raw TCP connections, reads the PROXY protocol header,
// terminates TLS itself while recording the ClientHello, and hands decrypted
// connections to an http.Server. Doing the handshake here (rather than in
// nginx) is what makes JA3/JA4 and HTTP/2 fingerprints observable.
type Listener struct {
	inner            net.Listener
	config           *tls.Config
	proxyProtocol    bool
	handshakeTimeout time.Duration
	conns            chan net.Conn
	done             chan struct{}
	closeOnce        sync.Once
	slots            chan struct{}
	debugf           func(format string, args ...any)
}

// ListenerOptions configures NewListener.
type ListenerOptions struct {
	ProxyProtocol    bool          // require a PROXY protocol header
	HandshakeTimeout time.Duration // PROXY header + TLS handshake budget
	MaxHandshakes    int           // concurrent handshakes in flight
	// Debugf, if set, receives failed PROXY headers and handshakes. The open
	// internet produces plenty of both, so it is off in production.
	Debugf func(format string, args ...any)
}

// NewListener wraps inner. config must provide certificates; ALPN should
// offer "h2" and "http/1.1". The listener installs its own
// GetConfigForClient hook, so config must not set one.
func NewListener(inner net.Listener, config *tls.Config, opts ListenerOptions) *Listener {
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.MaxHandshakes <= 0 {
		opts.MaxHandshakes = 256
	}
	cfg := config.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// The whole ClientHello has been read when this runs: stop copying
		// the stream so application data is never buffered.
		if rc, ok := hello.Conn.(*recordingConn); ok {
			rc.stop()
		}
		return nil, nil
	}
	l := &Listener{
		inner:            inner,
		config:           cfg,
		proxyProtocol:    opts.ProxyProtocol,
		handshakeTimeout: opts.HandshakeTimeout,
		conns:            make(chan net.Conn),
		done:             make(chan struct{}),
		slots:            make(chan struct{}, opts.MaxHandshakes),
		debugf:           opts.Debugf,
	}
	if l.debugf == nil {
		l.debugf = func(string, ...any) {}
	}
	go l.acceptLoop()
	return l
}

// Accept returns the next connection that completed its TLS handshake.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting connections.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.inner.Close()
	})
	return err
}

// Addr returns the listening address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

func (l *Listener) acceptLoop() {
	var backoff time.Duration
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors (EMFILE and friends): back off and retry.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			log.Printf("accept: %v; retrying in %v", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case l.slots <- struct{}{}:
			go func() {
				defer func() { <-l.slots }()
				l.handshake(raw)
			}()
		default:
			raw.Close() // overloaded: shed the connection instead of queueing
		}
	}
}

func (l *Listener) handshake(raw net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), l.handshakeTimeout)
	defer cancel()
	_ = raw.SetDeadline(time.Now().Add(l.handshakeTimeout))

	br := bufio.NewReaderSize(raw, 2048)
	remote := raw.RemoteAddr()
	if l.proxyProtocol {
		src, ok, err := ReadProxyHeader(br)
		if err != nil {
			l.debugf("%s: %v", raw.RemoteAddr(), err)
			raw.Close()
			return
		}
		if ok {
			remote = net.TCPAddrFromAddrPort(src)
		}
	}

	rc := &recordingConn{Conn: raw, r: br, limit: 16 << 10}
	tc := tls.Server(rc, l.config)
	if err := tc.HandshakeContext(ctx); err != nil {
		l.debugf("%s: TLS handshake: %v", remote, err)
		tc.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})

	hello, err := ParseClientHelloRecords(rc.bytes())
	c := &Conn{
		Conn:     tc,
		tls:      tc,
		remote:   remote,
		hello:    hello,
		helloErr: err,
		state:    tc.ConnectionState(),
		rec:      recorder{limit: 8 << 10},
	}
	rc.release()
	select {
	case l.conns <- c:
	case <-l.done:
		tc.Close()
	}
}

// recordingConn copies the first bytes read from the client (the
// ClientHello) while passing them through to crypto/tls.
type recordingConn struct {
	net.Conn
	r       io.Reader
	mu      sync.Mutex
	buf     []byte
	limit   int
	stopped bool
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.stopped {
			room := c.limit - len(c.buf)
			c.buf = append(c.buf, p[:min(n, max(room, 0))]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) stop() {
	c.mu.Lock()
	c.stopped = true
	c.mu.Unlock()
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf
}

func (c *recordingConn) release() {
	c.mu.Lock()
	c.stopped = true
	c.buf = nil
	c.mu.Unlock()
}

// recorder keeps the first decrypted bytes of a connection: the HTTP/2
// preface and frames, or the first HTTP/1.x request head.
type recorder struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (r *recorder) write(p []byte) {
	r.mu.Lock()
	if room := r.limit - len(r.buf); room > 0 {
		r.buf = append(r.buf, p[:min(len(p), room)]...)
	}
	r.mu.Unlock()
}

func (r *recorder) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

// Conn is a decrypted client connection plus everything observed while
// setting it up. It is what an http.Server sees from Listener.Accept.
type Conn struct {
	net.Conn
	tls      *tls.Conn
	remote   net.Addr
	hello    *ClientHello
	helloErr error
	state    tls.ConnectionState
	rec      recorder

	h2Once sync.Once
	h2     *H2Fingerprint
}

// Read records the beginning of the decrypted stream.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.tls.Read(p)
	if n > 0 {
		c.rec.write(p[:n])
	}
	return n, err
}

// RemoteAddr returns the original client address from the PROXY header.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// RemoteAddrPort is RemoteAddr as a netip.AddrPort.
func (c *Conn) RemoteAddrPort() netip.AddrPort {
	if a, ok := c.remote.(*net.TCPAddr); ok {
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(c.remote.String())
	return ap
}

// ClientHello returns the parsed ClientHello, or the parse error.
func (c *Conn) ClientHello() (*ClientHello, error) { return c.hello, c.helloErr }

// TLSState returns the negotiated TLS parameters.
func (c *Conn) TLSState() tls.ConnectionState { return c.state }

// H2 returns the HTTP/2 fingerprint of this connection, or nil for HTTP/1.x.
// Call it from a handler: by then the first HEADERS frame has been read.
func (c *Conn) H2() *H2Fingerprint {
	if c.state.NegotiatedProtocol != "h2" {
		return nil
	}
	c.h2Once.Do(func() {
		f, err := ParseH2(c.rec.snapshot())
		if err == nil && f.Complete {
			c.h2 = f
		}
	})
	return c.h2
}

// FirstRequestHeaderOrder returns the header names of the first HTTP/1.x
// request on this connection, in wire order.
func (c *Conn) FirstRequestHeaderOrder() []string {
	if c.state.NegotiatedProtocol == "h2" {
		return nil
	}
	return HeaderOrderH1(c.rec.snapshot())
}
