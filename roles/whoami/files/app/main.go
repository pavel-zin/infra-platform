// Command whoami shows visitors the identity websites can assign to their
// browser without cookies: client-side fingerprinting plus the TLS and HTTP/2
// fingerprints that only a server terminating TLS itself can see.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	_ "time/tzdata" // the image has no zoneinfo; time zone checks need it

	"whoami/internal/geo"
	"whoami/internal/netfp"
	"whoami/internal/store"
)

type config struct {
	Hostname      string // public name; other Host headers get 421
	Listen        string // TLS listener (behind the PROXY-protocol hop)
	HealthListen  string // plain HTTP, loopback only, for the container health check
	ProxyProtocol bool
	CertFile      string
	KeyFile       string
	SelfSigned    bool // development: generate a certificate for Hostname
	DataDir       string
	RetentionDays int
	MaxBrowsers   int
	GeoIP         string // "city", "country" or "off"
	Tor           bool
	STUN          string // used only when a visitor runs the WebRTC test
	HomeURL       string
	SourceURL     string
	Debug         bool // log failed handshakes and PROXY headers
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func loadConfig() config {
	return config{
		Hostname:      env("WHOAMI_HOSTNAME", ""),
		Listen:        env("WHOAMI_LISTEN", ":8443"),
		HealthListen:  env("WHOAMI_HEALTH_LISTEN", "127.0.0.1:8081"),
		ProxyProtocol: envBool("WHOAMI_PROXY_PROTOCOL", true),
		CertFile:      env("WHOAMI_CERT_FILE", ""),
		KeyFile:       env("WHOAMI_KEY_FILE", ""),
		SelfSigned:    envBool("WHOAMI_SELF_SIGNED", false),
		DataDir:       env("WHOAMI_DATA_DIR", "/data"),
		RetentionDays: envInt("WHOAMI_RETENTION_DAYS", 180),
		MaxBrowsers:   envInt("WHOAMI_MAX_BROWSERS", 50000),
		GeoIP:         env("WHOAMI_GEOIP", "city"),
		Tor:           envBool("WHOAMI_TOR", true),
		STUN:          env("WHOAMI_STUN", "stun:stun.cloudflare.com:3478"),
		HomeURL:       env("WHOAMI_HOME_URL", ""),
		SourceURL:     env("WHOAMI_SOURCE_URL", ""),
		Debug:         envBool("WHOAMI_DEBUG", false),
	}
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(loadConfig()))
	}
	if err := run(loadConfig()); err != nil {
		log.Fatal(err)
	}
}

// healthcheck is the container's HEALTHCHECK: the image has no shell or curl.
func healthcheck(cfg config) int {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + cfg.HealthListen + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, resp.Status)
		return 1
	}
	return 0
}

func run(cfg config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	keys, err := loadKeyring(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		return err
	}

	var certs *netfp.CertSource
	if cfg.SelfSigned {
		if certs, err = netfp.SelfSigned(cmpOr(cfg.Hostname, "localhost")); err != nil {
			return err
		}
	} else {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return errors.New("set WHOAMI_CERT_FILE and WHOAMI_KEY_FILE, or WHOAMI_SELF_SIGNED=true")
		}
		certs = netfp.NewCertSource(cfg.CertFile, cfg.KeyFile)
		if _, err := certs.Reload(); err != nil {
			log.Printf("certificate: %v (retrying every minute)", err)
		}
		go certs.Watch(ctx, time.Minute)
	}

	st := store.New(filepath.Join(cfg.DataDir, "store.gob"), time.Duration(cfg.RetentionDays)*24*time.Hour, cfg.MaxBrowsers)
	if err := st.Load(); err != nil {
		return err
	}
	go st.Run(ctx, 30*time.Second)

	feeds := &http.Client{Timeout: 15 * time.Minute}
	var geodb *geo.DBIP
	if cfg.GeoIP != "off" {
		geodb = &geo.DBIP{Dir: filepath.Join(cfg.DataDir, "geoip"), Edition: cfg.GeoIP, Client: feeds}
		geodb.Load()
		go geodb.Run(ctx)
	}
	var tor *geo.TorExits
	if cfg.Tor {
		tor = &geo.TorExits{URL: "https://check.torproject.org/torbulkexitlist", Cache: filepath.Join(cfg.DataDir, "tor-exits.txt"), Client: feeds}
		tor.Load()
		go tor.Run(ctx)
	}

	srv, err := newServer(cfg, keys, st, geodb, tor, certs)
	if err != nil {
		return err
	}

	inner, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	ln := netfp.NewListener(inner, &tls.Config{
		GetCertificate: certs.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	}, netfp.ListenerOptions{ProxyProtocol: cfg.ProxyProtocol, Debugf: debugf(cfg.Debug)})

	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // the listener already decrypted the stream
	public := &http.Server{
		Handler:           srv.handler(),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		ErrorLog: log.New(discardTLSNoise{}, "", 0),
	}
	health := &http.Server{
		Addr:              cfg.HealthListen,
		Handler:           http.HandlerFunc(srv.handleHealth),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 2)
	go func() { errc <- public.Serve(ln) }()
	go func() { errc <- health.ListenAndServe() }()
	log.Printf("whoami: serving https://%s on %s (PROXY protocol %v)", cmpOr(cfg.Hostname, "localhost"), cfg.Listen, cfg.ProxyProtocol)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = health.Shutdown(shutdown)
	_ = public.Shutdown(shutdown)
	// Let the store's final save run (it watches ctx).
	time.Sleep(200 * time.Millisecond)
	return st.Save()
}

func debugf(on bool) func(string, ...any) {
	if !on {
		return nil
	}
	return func(format string, args ...any) { log.Printf("debug: "+format, args...) }
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// discardTLSNoise drops the per-connection error lines net/http logs for
// clients that hang up mid-request; scanners on the open internet produce
// plenty of them and they carry nothing actionable.
type discardTLSNoise struct{}

func (discardTLSNoise) Write(p []byte) (int, error) { return len(p), nil }
