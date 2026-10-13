package geo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TorExits holds the Tor Project's list of exit relay addresses
// (https://check.torproject.org/torbulkexitlist), refreshed hourly and cached
// on disk so a restart does not forget it.
type TorExits struct {
	URL    string
	Cache  string
	Client *http.Client

	mu      sync.RWMutex
	set     map[netip.Addr]struct{}
	updated time.Time
}

// Contains reports whether ip is a current Tor exit.
func (t *TorExits) Contains(ip netip.Addr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.set[ip.Unmap()]
	return ok
}

// Size returns the number of known exits and when the list was fetched.
func (t *TorExits) Size() (int, time.Time) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.set), t.updated
}

func parseExitList(r io.Reader) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{})
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip, err := netip.ParseAddr(line); err == nil {
			set[ip.Unmap()] = struct{}{}
		}
	}
	return set
}

// Load reads the on-disk cache, if any.
func (t *TorExits) Load() {
	b, err := os.ReadFile(t.Cache)
	if err != nil {
		return
	}
	st, _ := os.Stat(t.Cache)
	set := parseExitList(bytes.NewReader(b))
	t.mu.Lock()
	t.set, t.updated = set, st.ModTime()
	t.mu.Unlock()
}

// Run refreshes the list every hour until ctx is cancelled.
func (t *TorExits) Run(ctx context.Context) {
	for {
		wait := time.Hour
		if err := t.fetch(ctx); err != nil {
			log.Printf("tor exit list: %v", err)
			wait = 10 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (t *TorExits) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return err
	}
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", t.URL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	set := parseExitList(bytes.NewReader(body))
	// A healthy list has over a thousand relays; refuse to replace it with
	// an error page or a truncated download.
	if len(set) < 100 {
		return fmt.Errorf("list has only %d addresses; keeping the previous one", len(set))
	}
	t.mu.Lock()
	t.set, t.updated = set, time.Now()
	t.mu.Unlock()
	if t.Cache != "" {
		tmp := t.Cache + ".tmp"
		if err := os.MkdirAll(filepath.Dir(t.Cache), 0o700); err == nil {
			if err := os.WriteFile(tmp, body, 0o600); err == nil {
				_ = os.Rename(tmp, t.Cache)
			}
		}
	}
	return nil
}
