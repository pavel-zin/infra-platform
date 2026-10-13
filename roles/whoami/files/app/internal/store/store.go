// Package store remembers fingerprints so the service can say "seen before"
// and "shared by N browsers". It holds only keyed hashes (HMAC-SHA256 under a
// secret that never leaves the data directory): no raw attribute values, no IP
// addresses, no User-Agent strings beyond a coarse "Firefox on macOS" label.
package store

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// ID is a 128-bit identifier derived from a fingerprint.
type ID [16]byte

// Browser is one distinct browser fingerprint.
type Browser struct {
	First, Last int64    // unix seconds
	Visits      uint32   // scans with this exact fingerprint
	Device      ID       // cross-browser device fingerprint
	Network     uint64   // keyed hash of the last IP address it came from
	Label       string   // coarse description, e.g. "Firefox on macOS"
	Attrs       []uint64 // keyed hashes of its attribute values
	Cookies     []uint64 // keyed hashes of the cookie IDs seen with it (capped)
}

// Cookie is one first-party cookie ID handed out by the service.
type Cookie struct {
	First, Last int64
	Browser     ID // fingerprint it was last seen with
}

type state struct {
	Version  int
	Browsers map[ID]*Browser
	Cookies  map[ID]*Cookie
	Attrs    map[uint64]uint32 // attribute value hash -> number of browsers
}

const stateVersion = 1

// maxCookiesPerBrowser bounds how many distinct cookies are remembered per
// fingerprint; it is also the ceiling of "shared by N people".
const maxCookiesPerBrowser = 64

// Store is an in-memory database persisted to a single file.
type Store struct {
	path        string
	retention   time.Duration
	maxBrowsers int

	mu    sync.Mutex
	st    state
	dirty bool
}

// New returns an empty store backed by path.
func New(path string, retention time.Duration, maxBrowsers int) *Store {
	return &Store{path: path, retention: retention, maxBrowsers: maxBrowsers, st: emptyState()}
}

func emptyState() state {
	return state{Version: stateVersion, Browsers: map[ID]*Browser{}, Cookies: map[ID]*Cookie{}, Attrs: map[uint64]uint32{}}
}

// Load reads the snapshot file. A missing file is an empty store.
func (s *Store) Load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st state
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&st); err != nil {
		return fmt.Errorf("store %s: %w", s.path, err)
	}
	if st.Version != stateVersion {
		return fmt.Errorf("store %s: unsupported version %d", s.path, st.Version)
	}
	if st.Browsers == nil {
		st.Browsers = map[ID]*Browser{}
	}
	if st.Cookies == nil {
		st.Cookies = map[ID]*Cookie{}
	}
	if st.Attrs == nil {
		st.Attrs = map[uint64]uint32{}
	}
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
	return nil
}

// Save writes a snapshot atomically if anything changed.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(&s.st)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path, buf.Bytes()); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".store-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Run saves periodically and expires old records until ctx is done, then
// saves one last time.
func (s *Store) Run(ctx context.Context, every time.Duration) {
	save := time.NewTicker(every)
	sweep := time.NewTicker(time.Hour)
	defer save.Stop()
	defer sweep.Stop()
	s.Expire(time.Now())
	for {
		select {
		case <-ctx.Done():
			if err := s.Save(); err != nil {
				log.Printf("store: final save: %v", err)
			}
			return
		case <-save.C:
			if err := s.Save(); err != nil {
				log.Printf("store: save: %v", err)
			}
		case now := <-sweep.C:
			s.Expire(now)
		}
	}
}

// Observation is one scan.
type Observation struct {
	Browser ID
	Device  ID
	Network uint64
	Label   string
	Attrs   []uint64 // hashes of the attributes that make up Browser
	Cookie  *ID      // nil when the browser refused the cookie
	Now     time.Time
}

// Sibling is another browser fingerprint seen on the same device and network.
type Sibling struct {
	Browser ID
	Label   string
	Last    time.Time
}

// Result is what the store knows about an observation, after recording it.
type Result struct {
	Seen          bool      // this browser fingerprint was recorded before
	First         time.Time // first time it was recorded
	Visits        uint32    // including this one
	People        int       // distinct cookies seen with this fingerprint
	CookieSeen    bool      // the cookie was issued on an earlier visit
	CookieFirst   time.Time
	CookieMoved   bool // the cookie was last seen with a different fingerprint
	Siblings      []Sibling
	Total         int      // browsers in the store
	AttrCounts    []uint32 // browsers sharing each attribute value (same order as Attrs)
	DeviceMatches int      // browsers with the same device fingerprint (any network)
}

func cookieHash(c ID) uint64 {
	var h uint64
	for _, b := range c[:8] {
		h = h<<8 | uint64(b)
	}
	return h
}

// Observe records a scan and reports what was known before it.
func (s *Store) Observe(o Observation) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := o.Now.Unix()
	s.dirty = true

	var r Result
	b, ok := s.st.Browsers[o.Browser]
	if ok {
		r.Seen, r.First = true, time.Unix(b.First, 0)
		b.Visits++
		b.Last = now
		b.Network = o.Network
		b.Device = o.Device
		if o.Label != "" {
			b.Label = o.Label
		}
	} else {
		if s.maxBrowsers > 0 && len(s.st.Browsers) >= s.maxBrowsers {
			s.evictOldest(len(s.st.Browsers) - s.maxBrowsers + 1 + s.maxBrowsers/100)
		}
		b = &Browser{First: now, Last: now, Visits: 1, Device: o.Device, Network: o.Network, Label: o.Label, Attrs: slices.Clone(o.Attrs)}
		s.st.Browsers[o.Browser] = b
		for _, a := range b.Attrs {
			s.st.Attrs[a]++
		}
		r.First = o.Now
	}
	r.Visits = b.Visits

	if o.Cookie != nil {
		if c, ok := s.st.Cookies[*o.Cookie]; ok {
			r.CookieSeen, r.CookieFirst = true, time.Unix(c.First, 0)
			r.CookieMoved = c.Browser != o.Browser
			c.Last, c.Browser = now, o.Browser
		} else {
			s.st.Cookies[*o.Cookie] = &Cookie{First: now, Last: now, Browser: o.Browser}
			r.CookieFirst = o.Now
		}
		h := cookieHash(*o.Cookie)
		if !slices.Contains(b.Cookies, h) && len(b.Cookies) < maxCookiesPerBrowser {
			b.Cookies = append(b.Cookies, h)
		}
	}
	r.People = len(b.Cookies)

	for id, other := range s.st.Browsers {
		if other.Device != o.Device {
			continue
		}
		r.DeviceMatches++
		if id != o.Browser && other.Network == o.Network {
			r.Siblings = append(r.Siblings, Sibling{Browser: id, Label: other.Label, Last: time.Unix(other.Last, 0)})
		}
	}
	sort.Slice(r.Siblings, func(i, j int) bool { return r.Siblings[i].Last.After(r.Siblings[j].Last) })
	if len(r.Siblings) > 4 {
		r.Siblings = r.Siblings[:4]
	}

	r.Total = len(s.st.Browsers)
	r.AttrCounts = make([]uint32, len(o.Attrs))
	for i, a := range o.Attrs {
		r.AttrCounts[i] = s.st.Attrs[a]
	}
	return r
}

// removeLocked deletes a browser and releases its attribute counts.
func (s *Store) removeLocked(id ID) bool {
	b, ok := s.st.Browsers[id]
	if !ok {
		return false
	}
	for _, a := range b.Attrs {
		if n := s.st.Attrs[a]; n <= 1 {
			delete(s.st.Attrs, a)
		} else {
			s.st.Attrs[a] = n - 1
		}
	}
	delete(s.st.Browsers, id)
	return true
}

func (s *Store) evictOldest(n int) {
	type aged struct {
		id   ID
		last int64
	}
	all := make([]aged, 0, len(s.st.Browsers))
	for id, b := range s.st.Browsers {
		all = append(all, aged{id, b.Last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last < all[j].last })
	for i := 0; i < n && i < len(all); i++ {
		s.removeLocked(all[i].id)
	}
}

// Forget deletes a browser fingerprint and, if given, the cookie record.
func (s *Store) Forget(browser ID, cookie *ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := s.removeLocked(browser)
	if cookie != nil {
		if _, ok := s.st.Cookies[*cookie]; ok {
			delete(s.st.Cookies, *cookie)
			removed = true
		}
	}
	if removed {
		s.dirty = true
	}
	return removed
}

// Expire drops records not seen within the retention period.
func (s *Store) Expire(now time.Time) (browsers, cookies int) {
	if s.retention <= 0 {
		return 0, 0
	}
	cutoff := now.Add(-s.retention).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, b := range s.st.Browsers {
		if b.Last < cutoff && s.removeLocked(id) {
			browsers++
		}
	}
	for id, c := range s.st.Cookies {
		if c.Last < cutoff {
			delete(s.st.Cookies, id)
			cookies++
		}
	}
	if browsers+cookies > 0 {
		s.dirty = true
	}
	return browsers, cookies
}

// Counts returns the number of stored browsers and cookies.
func (s *Store) Counts() (browsers, cookies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.Browsers), len(s.st.Cookies)
}
