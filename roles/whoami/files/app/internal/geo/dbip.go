package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Location is what the city database says about an address.
type Location struct {
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"countryCode,omitempty"`
	Continent   string  `json:"continent,omitempty"`
	Latitude    float64 `json:"lat,omitempty"`
	Longitude   float64 `json:"lon,omitempty"`
	EU          bool    `json:"eu,omitempty"`
}

// Network is the autonomous system that announces an address.
type Network struct {
	ASN uint64 `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
}

// DBIP keeps DB-IP Lite databases (CC BY 4.0, https://db-ip.com) on disk and
// refreshes them monthly. DB-IP publishes new Lite editions at the start of
// each month under predictable URLs; no account or key is needed.
type DBIP struct {
	Dir     string // where the .mmdb files live
	Edition string // "city" or "country"
	BaseURL string // defaults to https://download.db-ip.com/free
	Client  *http.Client

	mu  sync.RWMutex
	loc *Reader
	asn *Reader
}

func (d *DBIP) path(kind string) string {
	return filepath.Join(d.Dir, "dbip-"+kind+"-lite.mmdb")
}

// Load opens whatever databases are already on disk.
func (d *DBIP) Load() {
	for _, kind := range []string{d.Edition, "asn"} {
		r, err := Open(d.path(kind))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("geoip: %s: %v", kind, err)
			}
			continue
		}
		d.swap(kind, r)
	}
}

func (d *DBIP) swap(kind string, r *Reader) {
	d.mu.Lock()
	var old *Reader
	if kind == "asn" {
		old, d.asn = d.asn, r
	} else {
		old, d.loc = d.loc, r
	}
	d.mu.Unlock()
	if old != nil {
		// Lookups hold the read lock for their whole duration, so once the
		// write lock above was acquired no reader still uses the old mapping.
		_ = old.Close()
	}
}

// Lookup returns location and network data for ip. Missing databases or
// unknown addresses yield zero values.
func (d *DBIP) Lookup(ip netip.Addr) (Location, Network) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var loc Location
	var nw Network
	if d.loc != nil {
		if rec, ok, err := d.loc.Lookup(ip); err == nil && ok {
			loc = locationFrom(rec)
		}
	}
	if d.asn != nil {
		if rec, ok, err := d.asn.Lookup(ip); err == nil && ok {
			if m, ok := rec.(map[string]any); ok {
				nw.ASN = asUint(m["autonomous_system_number"])
				nw.Org, _ = m["autonomous_system_organization"].(string)
			}
		}
	}
	return loc, nw
}

func path(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func str(v any, keys ...string) string {
	s, _ := path(v, keys...).(string)
	return s
}

func locationFrom(rec any) Location {
	loc := Location{
		City:        str(rec, "city", "names", "en"),
		Country:     str(rec, "country", "names", "en"),
		CountryCode: str(rec, "country", "iso_code"),
		Continent:   str(rec, "continent", "names", "en"),
	}
	loc.Latitude, _ = path(rec, "location", "latitude").(float64)
	loc.Longitude, _ = path(rec, "location", "longitude").(float64)
	loc.EU, _ = path(rec, "country", "is_in_european_union").(bool)
	if subs, ok := path(rec, "subdivisions").([]any); ok && len(subs) > 0 {
		loc.Region = str(subs[0], "names", "en")
	}
	return loc
}

// Built returns the build dates of the loaded databases.
func (d *DBIP) Built() (location, network time.Time) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.loc != nil {
		location = time.Unix(int64(d.loc.Metadata.BuildEpoch), 0).UTC()
	}
	if d.asn != nil {
		network = time.Unix(int64(d.asn.Metadata.BuildEpoch), 0).UTC()
	}
	return
}

// Run downloads missing or outdated databases now and then every few hours
// until ctx is cancelled. Failures are logged and retried; the service keeps
// answering with whatever it has.
func (d *DBIP) Run(ctx context.Context) {
	for {
		wait := 6 * time.Hour
		for _, kind := range []string{d.Edition, "asn"} {
			if err := d.refresh(ctx, kind); err != nil {
				log.Printf("geoip: %s: %v", kind, err)
				wait = 30 * time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (d *DBIP) current(kind string) *Reader {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if kind == "asn" {
		return d.asn
	}
	return d.loc
}

func (d *DBIP) refresh(ctx context.Context, kind string) error {
	now := time.Now().UTC()
	edition := now.Format("2006-01")
	if r := d.current(kind); r != nil {
		// The edition label is recorded next to the file on download; the
		// build date is the fallback for files placed there by hand.
		if b, err := os.ReadFile(d.path(kind) + ".edition"); err == nil {
			if string(b) == edition {
				return nil
			}
		} else if time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format("2006-01") == edition {
			return nil
		}
	}
	// This month's edition appears a few hours into the 1st. Until then keep
	// what we have; with nothing on disk at all, take last month's.
	months := []time.Time{now}
	if d.current(kind) == nil {
		months = append(months, now.AddDate(0, 0, -now.Day()))
	}
	var err error
	for _, month := range months {
		url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", d.baseURL(), kind, month.Format("2006-01"))
		if err = d.download(ctx, url, d.path(kind)); err == nil {
			r, err := Open(d.path(kind))
			if err != nil {
				return err
			}
			_ = os.WriteFile(d.path(kind)+".edition", []byte(month.Format("2006-01")), 0o600)
			d.swap(kind, r)
			log.Printf("geoip: loaded %s (built %s)", url, time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format(time.DateOnly))
			return nil
		}
		if !errors.Is(err, errNotPublished) {
			return err
		}
	}
	if d.current(kind) != nil {
		return nil // not published yet; check again on the next round
	}
	return err
}

func (d *DBIP) baseURL() string {
	if d.BaseURL != "" {
		return d.BaseURL
	}
	return "https://download.db-ip.com/free"
}

var errNotPublished = errors.New("edition not published yet")

// download fetches a gzipped database and atomically replaces dst with it
// once it parses.
func (d *DBIP) download(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "whoami-fingerprint-service (+https://github.com/pavel-zin/infra-platform)")
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotPublished
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// 1 GiB ceiling: today's city edition is about 130 MB uncompressed.
	if _, err := io.Copy(tmp, io.LimitReader(gz, 1<<30)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	check, err := Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid database: %w", err)
	}
	_ = check.Close()
	return os.Rename(tmp.Name(), dst)
}
