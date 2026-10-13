package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"whoami/internal/geo"
	"whoami/internal/netfp"
	"whoami/internal/store"
)

//go:embed web
var webFS embed.FS

type server struct {
	cfg     config
	keys    *keyring
	store   *store.Store
	geo     *geo.DBIP
	tor     *geo.TorExits
	certs   *netfp.CertSource
	scans   *limiter
	forgets *limiter
	index   *template.Template
	static  http.Handler
}

func newServer(cfg config, keys *keyring, st *store.Store, g *geo.DBIP, tor *geo.TorExits, certs *netfp.CertSource) (*server, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	index, err := template.ParseFS(sub, "index.html")
	if err != nil {
		return nil, err
	}
	return &server{
		cfg: cfg, keys: keys, store: st, geo: g, tor: tor, certs: certs,
		scans:   newLimiter(12, 12),
		forgets: newLimiter(12, 12),
		index:   index,
		static:  http.FileServerFS(sub),
	}, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/tls", s.handleTLS)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("POST /api/forget", s.handleForget)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})
	return s.checkHost(securityHeaders(mux))
}

// checkHost answers 421 Misdirected Request for other hostnames. The edge
// certificate covers several names on one address, so a browser may reuse a
// connection to this service for a request meant for another site; 421 tells
// it to open a fresh connection, which nginx then routes correctly.
func (s *server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Hostname != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !strings.EqualFold(host, s.cfg.Hostname) {
				http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"font-src 'self'; connect-src 'self'; worker-src 'self' blob:; frame-src 'self'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	s.static.ServeHTTP(w, r)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.certs != nil && !s.certs.Ready() {
		http.Error(w, "certificate not loaded", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// --- what the server sees about a connection ---

type connKey struct{}

func connFrom(r *http.Request) *netfp.Conn {
	c, _ := r.Context().Value(connKey{}).(*netfp.Conn)
	return c
}

func clientAddr(r *http.Request) netip.Addr {
	if c := connFrom(r); c != nil {
		return c.RemoteAddrPort().Addr()
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

type tlsView struct {
	Version     string   `json:"version"`
	Cipher      string   `json:"cipher"`
	ALPN        string   `json:"alpn"`
	SNI         string   `json:"sni"`
	JA3         string   `json:"ja3"`
	JA3Hash     string   `json:"ja3Hash"`
	JA4         string   `json:"ja4"`
	JA4R        string   `json:"ja4r"`
	Family      string   `json:"family"`
	FamilyName  string   `json:"familyName"`
	Groups      []string `json:"groups"`
	KeyShares   []string `json:"keyShares"`
	PostQuantum bool     `json:"postQuantum"`
	GREASE      bool     `json:"grease"`
	Ciphers     int      `json:"ciphers"`
	Extensions  int      `json:"extensions"`
	ECH         bool     `json:"ech"`
}

type h2Setting struct {
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}

type h2View struct {
	Akamai        string      `json:"akamai"`
	Settings      []h2Setting `json:"settings"`
	WindowUpdate  uint32      `json:"windowUpdate"`
	Priorities    int         `json:"priorities"`
	PseudoHeaders string      `json:"pseudoHeaders"`
	Family        string      `json:"family"`
	FamilyName    string      `json:"familyName"`
}

type ipView struct {
	Address  string       `json:"address"`
	Version  int          `json:"version"`
	RDNS     string       `json:"rdns,omitempty"`
	Location geo.Location `json:"location"`
	Network  geo.Network  `json:"network"`
	Tor      bool         `json:"tor"`
	Hosting  bool         `json:"hosting"`
}

type serverView struct {
	Protocol    string      `json:"protocol"`
	IP          ipView      `json:"ip"`
	TLS         *tlsView    `json:"tls"`
	HTTP2       *h2View     `json:"http2"`
	HeaderOrder []string    `json:"headerOrder,omitempty"`
	Headers     [][2]string `json:"headers"`
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// hiddenHeaders are never echoed back: credentials, and transport headers
// that describe the request body rather than the browser.
var hiddenHeaders = map[string]bool{
	"cookie": true, "authorization": true, "proxy-authorization": true,
	"content-length": true, "content-type": true,
}

func (s *server) view(ctx context.Context, r *http.Request, withRDNS bool) serverView {
	v := serverView{Protocol: r.Proto}
	ip := clientAddr(r)
	if ip.IsValid() {
		v.IP.Address = ip.String()
		v.IP.Version = 4
		if ip.Is6() {
			v.IP.Version = 6
		}
		if s.geo != nil {
			v.IP.Location, v.IP.Network = s.geo.Lookup(ip)
		}
		if s.tor != nil {
			v.IP.Tor = s.tor.Contains(ip)
		}
		v.IP.Hosting = geo.IsHosting(v.IP.Network)
		if withRDNS && !ip.IsPrivate() && !ip.IsLoopback() {
			rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			if names, err := net.DefaultResolver.LookupAddr(rctx, ip.String()); err == nil && len(names) > 0 {
				v.IP.RDNS = strings.TrimSuffix(names[0], ".")
			}
			cancel()
		}
	}
	if c := connFrom(r); c != nil {
		st := c.TLSState()
		t := &tlsView{Version: tlsVersionName(st.Version), Cipher: tls.CipherSuiteName(st.CipherSuite), ALPN: st.NegotiatedProtocol}
		if h, err := c.ClientHello(); err == nil && h != nil {
			t.SNI = h.ServerName
			t.JA3, t.JA3Hash = h.JA3()
			t.JA4, t.JA4R = h.JA4()
			t.Family = h.Family()
			t.FamilyName = netfp.FamilyName(t.Family)
			t.GREASE = h.HasGREASE()
			for _, g := range h.SupportedGroups {
				if !netfp.IsGREASE(g) {
					t.Groups = append(t.Groups, netfp.GroupName(g))
				}
			}
			for _, g := range h.KeyShareGroups {
				if !netfp.IsGREASE(g) {
					t.KeyShares = append(t.KeyShares, netfp.GroupName(g))
					t.PostQuantum = t.PostQuantum || strings.Contains(netfp.GroupName(g), "MLKEM") || strings.Contains(netfp.GroupName(g), "Kyber")
				}
			}
			for _, x := range h.CipherSuites {
				if !netfp.IsGREASE(x) {
					t.Ciphers++
				}
			}
			for _, x := range h.Extensions {
				if !netfp.IsGREASE(x) {
					t.Extensions++
				}
				t.ECH = t.ECH || x == 0xfe0d
			}
		}
		v.TLS = t
		if f := c.H2(); f != nil {
			h := &h2View{Akamai: f.Akamai(), WindowUpdate: f.WindowUpdate, Priorities: len(f.Priorities), Family: f.Family()}
			h.FamilyName = netfp.FamilyName(h.Family)
			for _, st := range f.Settings {
				h.Settings = append(h.Settings, h2Setting{Name: netfp.SettingName(st.ID), Value: st.Value})
			}
			pseudo := make([]string, len(f.PseudoHeaders))
			copy(pseudo, f.PseudoHeaders)
			h.PseudoHeaders = strings.Join(pseudo, ", ")
			v.HTTP2 = h
		}
		v.HeaderOrder = c.FirstRequestHeaderOrder()
	}
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		if !hiddenHeaders[strings.ToLower(k)] {
			names = append(names, k)
		}
	}
	if len(v.HeaderOrder) > 0 {
		pos := func(k string) int {
			if i := slices.Index(v.HeaderOrder, strings.ToLower(k)); i >= 0 {
				return i
			}
			return len(v.HeaderOrder)
		}
		sort.SliceStable(names, func(i, j int) bool { return pos(names[i]) < pos(names[j]) })
	} else {
		sort.Strings(names)
	}
	for _, k := range names {
		v.Headers = append(v.Headers, [2]string{strings.ToLower(k), shorten(strings.Join(r.Header.Values(k), ", "), 300)})
	}
	return v
}

// --- index page ---

// acceptCH asks Chromium for the high-entropy client hints on later requests,
// as many large sites do, to show what a server receives without any script.
const acceptCH = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, " +
	"Sec-CH-UA-Model, Sec-CH-UA-Form-Factors, Sec-CH-Prefers-Color-Scheme, Sec-CH-Prefers-Reduced-Motion, " +
	"Device-Memory, Downlink, ECT, RTT"

type indexData struct {
	Server        serverView
	Hostname      string
	HomeURL       string
	HomeLabel     string
	SourceURL     string
	STUN          string
	RetentionDays int
}

func wantsText(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return !strings.Contains(accept, "text/html")
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Accept-CH", acceptCH)
	w.Header().Set("Vary", "Accept")
	if wantsText(r) {
		s.writeText(w, r)
		return
	}
	data := indexData{
		Server:        s.view(r.Context(), r, false),
		Hostname:      s.cfg.Hostname,
		HomeURL:       s.cfg.HomeURL,
		HomeLabel:     strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s.cfg.HomeURL, "https://"), "http://"), "/"),
		SourceURL:     s.cfg.SourceURL,
		STUN:          s.cfg.STUN,
		RetentionDays: s.cfg.RetentionDays,
	}
	var buf bytes.Buffer
	if err := s.index.Execute(&buf, data); err != nil {
		log.Printf("index: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *server) handleTLS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.view(r.Context(), r, true))
}

// writeText answers curl and other non-browser clients with what their
// connection gave away.
func (s *server) writeText(w http.ResponseWriter, r *http.Request) {
	v := s.view(r.Context(), r, true)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var b strings.Builder
	row := func(k, val string) {
		if val != "" {
			fmt.Fprintf(&b, "%-14s %s\n", k, val)
		}
	}
	fmt.Fprintf(&b, "%s: what this connection reveals before any script runs\n\n", s.cfg.Hostname)
	row("IP address", v.IP.Address)
	if v.IP.Network.ASN != 0 {
		row("Network", fmt.Sprintf("AS%d %s", v.IP.Network.ASN, v.IP.Network.Org))
	}
	row("Location", strings.Join(nonEmpty(v.IP.Location.City, v.IP.Location.Region, v.IP.Location.Country), ", "))
	row("Reverse DNS", v.IP.RDNS)
	if v.IP.Tor {
		row("Tor", "yes, this is a Tor exit relay")
	}
	if v.TLS != nil {
		row("Protocol", fmt.Sprintf("%s over %s (%s)", v.Protocol, v.TLS.Version, v.TLS.Cipher))
		row("JA4", v.TLS.JA4)
		row("JA3", v.TLS.JA3Hash)
		row("TLS stack", v.TLS.FamilyName+" (heuristic)")
	}
	if v.HTTP2 != nil {
		row("HTTP/2", v.HTTP2.Akamai)
	}
	if len(v.HeaderOrder) > 0 {
		row("Header order", strings.Join(v.HeaderOrder, ", "))
	}
	row("User-Agent", r.UserAgent())
	fmt.Fprintf(&b, "\nOpen https://%s in a browser for the full test.\n", s.cfg.Hostname)
	_, _ = io.WriteString(w, b.String())
}

func nonEmpty(v ...string) []string {
	out := v[:0:0]
	for _, s := range v {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
