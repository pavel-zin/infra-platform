package netfp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertSource serves a certificate from disk and picks up renewals: certbot
// replaces the files behind the live/ symlinks, and the next Reload (on a
// timer) notices the changed target and loads it without a restart.
type CertSource struct {
	certFile, keyFile string

	mu    sync.RWMutex
	cert  *tls.Certificate
	leaf  *x509.Certificate
	stamp string
	err   error
}

// NewCertSource returns a source for the given PEM files.
func NewCertSource(certFile, keyFile string) *CertSource {
	return &CertSource{certFile: certFile, keyFile: keyFile}
}

func fileStamp(path string) (string, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(target)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s@%d:%d", target, st.ModTime().UnixNano(), st.Size()), nil
}

// Reload loads the files if they changed since the last successful load.
func (s *CertSource) Reload() (changed bool, err error) {
	cs, err := fileStamp(s.certFile)
	if err != nil {
		return false, s.fail(err)
	}
	ks, err := fileStamp(s.keyFile)
	if err != nil {
		return false, s.fail(err)
	}
	stamp := cs + "|" + ks
	s.mu.RLock()
	same := stamp == s.stamp
	s.mu.RUnlock()
	if same {
		return false, nil
	}
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return false, s.fail(err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return false, s.fail(err)
		}
	}
	s.mu.Lock()
	s.cert, s.leaf, s.stamp, s.err = &cert, cert.Leaf, stamp, nil
	s.mu.Unlock()
	return true, nil
}

func (s *CertSource) fail(err error) error {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	return err
}

// Watch reloads the certificate every interval until ctx is done.
func (s *CertSource) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if changed, err := s.Reload(); err != nil {
				log.Printf("certificate: %v", err)
			} else if changed {
				log.Printf("certificate: loaded %s (expires %s)", s.certFile, s.NotAfter().Format(time.DateOnly))
			}
		}
	}
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *CertSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil {
		if s.err != nil {
			return nil, s.err
		}
		return nil, errors.New("certificate not loaded")
	}
	return s.cert, nil
}

// Ready reports whether a certificate is loaded.
func (s *CertSource) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert != nil
}

// NotAfter returns the expiry of the loaded certificate.
func (s *CertSource) NotAfter() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil {
		return time.Time{}
	}
	return s.leaf.NotAfter
}

// SelfSigned returns a source holding a fresh self-signed certificate for
// hostname, for local development and tests.
func SelfSigned(hostname string) (*CertSource, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return &CertSource{cert: cert, leaf: leaf, stamp: "self-signed"}, nil
}
