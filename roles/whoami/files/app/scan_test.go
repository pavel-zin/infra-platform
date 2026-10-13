package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"whoami/internal/store"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	keys, err := loadKeyring(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{Hostname: "whoami.test", RetentionDays: 180, STUN: "stun:stun.example.test:3478",
		HomeURL: "https://example.test/", SourceURL: "https://example.test/source"}
	st := store.New(filepath.Join(dir, "store.gob"), 180*24*time.Hour, 0)
	srv, err := newServer(cfg, keys, st, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return srv.handler()
}

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
const firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0"

// chromeSignals is a plausible subset of what the page sends from Chrome.
func chromeSignals() map[string]any {
	return map[string]any{
		"nav.userAgent":     chromeUA,
		"nav.platform":      "Linux x86_64",
		"nav.languages":     []string{"fr-FR", "fr", "en"},
		"uach.brands":       map[string]any{"brands": []string{"Google Chrome 141", "Chromium 141"}, "mobile": false, "platform": "Linux"},
		"uach.highEntropy":  map[string]any{"fullVersionList": []string{"Google Chrome 141.0.7390.55", "Chromium 141.0.7390.55"}, "platform": "Linux", "platformVersion": "6.8.0", "architecture": "x86"},
		"intl.timeZone":     "Europe/Paris",
		"screen.size":       "1920x1080",
		"screen.colorDepth": 24,
		"screen.dpr":        1,
		"css.colorScheme":   "light",
		"hw.cores":          8,
		"hw.touch":          map[string]any{"points": 0, "events": false},
		"gpu.webgl":         map[string]any{"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620)"},
		"canvas.2d":         "0123456789abcdef",
		"fonts.installed":   []string{"DejaVu Sans", "Liberation Sans", "Noto Color Emoji"},
		"window.size":       map[string]any{"inner": "1280x800", "outer": "1280x900"},
		"media.devices":     map[string]any{"audioinput": 1, "audiooutput": 1, "videoinput": 0},
	}
}

func firefoxSignals() map[string]any {
	s := chromeSignals()
	s["nav.userAgent"] = firefoxUA
	s["uach.brands"], s["uach.highEntropy"] = nil, nil
	s["gpu.webgl"] = map[string]any{"vendor": "Intel", "renderer": "Intel(R) HD Graphics, or similar"}
	s["canvas.2d"] = "fedcba9876543210"
	return s
}

type scanResult struct {
	resp   scanResponse
	cookie *http.Cookie
	status int
}

func doScan(t *testing.T, h http.Handler, ua string, signals map[string]any, cookie *http.Cookie) scanResult {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"signals": signals})
	req := httptest.NewRequest(http.MethodPost, "https://whoami.test/api/scan", bytes.NewReader(body))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
	req.RemoteAddr = "192.0.2.10:50000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := scanResult{status: rec.Code}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.resp); err != nil {
			t.Fatalf("decoding %s: %v", rec.Body.String(), err)
		}
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			out.cookie = c
		}
	}
	return out
}

func TestScanLifecycle(t *testing.T) {
	h := testServer(t)

	first := doScan(t, h, chromeUA, chromeSignals(), nil)
	if first.status != 200 || first.resp.Browser.Seen || first.resp.Cookie.Status != "new" || first.cookie == nil {
		t.Fatalf("first scan: status %d %+v", first.status, first.resp.Browser)
	}
	if !first.cookie.Secure || !first.cookie.HttpOnly {
		t.Fatalf("cookie flags: %+v", first.cookie)
	}
	name := first.resp.Browser.Persona.Name

	// A private window: no cookie, same fingerprint.
	private := doScan(t, h, chromeUA, chromeSignals(), nil)
	if !private.resp.RecognizedWithoutCookie || private.resp.Browser.Persona.Name != name {
		t.Fatalf("private window not recognized: %+v", private.resp.Browser)
	}

	// Back in the normal window, cookie intact.
	back := doScan(t, h, chromeUA, chromeSignals(), first.cookie)
	if !back.resp.Browser.Seen || back.resp.Cookie.Status != "returning" || back.resp.RecognizedWithoutCookie {
		t.Fatalf("returning visit: %+v cookie %s", back.resp.Browser, back.resp.Cookie.Status)
	}
	if back.resp.Browser.Visits != 3 || back.resp.Browser.People != 2 {
		t.Fatalf("visits %d people %d", back.resp.Browser.Visits, back.resp.Browser.People)
	}

	// The fingerprint changes (say, a canvas-randomizing extension) but the
	// cookie stays: the cookie has "moved".
	changed := chromeSignals()
	changed["canvas.2d"] = "1111111111111111"
	moved := doScan(t, h, chromeUA, changed, first.cookie)
	if moved.resp.Browser.Seen || moved.resp.Cookie.Status != "moved" || moved.resp.Browser.Persona.Name == name {
		t.Fatalf("changed fingerprint: %+v cookie %s", moved.resp.Browser, moved.resp.Cookie.Status)
	}

	// Forget it; the next scan starts from nothing.
	body, _ := json.Marshal(map[string]string{"browser": moved.resp.Browser.ID})
	req := httptest.NewRequest(http.MethodPost, "https://whoami.test/api/forget", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.10:50001"
	req.AddCookie(first.cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"forgotten":true`) {
		t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
	}
	again := doScan(t, h, chromeUA, changed, nil)
	if again.resp.Browser.Seen {
		t.Fatal("forgotten browser was recognized")
	}
}

func TestScanStability(t *testing.T) {
	h := testServer(t)
	base := doScan(t, h, chromeUA, chromeSignals(), nil).resp

	// Zoom, theme, window size, headsets and a Chrome patch release must not
	// rename the browser.
	s := chromeSignals()
	s["screen.dpr"] = 1.25
	s["css.colorScheme"] = "dark"
	s["window.size"] = map[string]any{"inner": "900x700", "outer": "900x800"}
	s["media.devices"] = map[string]any{"audioinput": 2, "audiooutput": 2, "videoinput": 1}
	s["uach.highEntropy"] = map[string]any{"fullVersionList": []string{"Google Chrome 141.0.7390.122", "Chromium 141.0.7390.122"}, "platform": "Linux", "platformVersion": "6.8.12", "architecture": "x86"}
	same := doScan(t, h, chromeUA, s, nil).resp
	if same.Browser.ID != base.Browser.ID {
		t.Fatal("volatile changes produced a new browser ID")
	}

	// A new Chrome major version does.
	s["uach.highEntropy"] = map[string]any{"fullVersionList": []string{"Google Chrome 142.0.7444.10", "Chromium 142.0.7444.10"}, "platform": "Linux", "platformVersion": "6.8.12", "architecture": "x86"}
	if doScan(t, h, chromeUA, s, nil).resp.Browser.ID == base.Browser.ID {
		t.Fatal("a major version change kept the browser ID")
	}

	// Firefox on the same computer: new browser name, same device name, and
	// the earlier Chrome scan is listed as a sibling.
	ff := doScan(t, h, firefoxUA, firefoxSignals(), nil).resp
	if ff.Browser.ID == base.Browser.ID {
		t.Fatal("Firefox and Chrome got the same browser ID")
	}
	if ff.Device.Persona.Code != base.Device.Persona.Code {
		t.Fatalf("device changed between browsers: %s vs %s", ff.Device.Persona.Code, base.Device.Persona.Code)
	}
	if len(ff.Device.Siblings) == 0 || !strings.HasPrefix(ff.Device.Siblings[0].Label, "Chrome 14") {
		t.Fatalf("siblings = %+v", ff.Device.Siblings)
	}
	if ff.UA.Label != "Firefox 155 on Linux" {
		t.Fatalf("label = %q", ff.UA.Label)
	}

	// Rarity statistics count stored browsers sharing each value.
	stats := map[string]attrStat{}
	for _, st := range ff.Stats {
		stats[st.Key] = st
	}
	// Three browsers are stored: Chrome 141, Chrome 142 and Firefox.
	if st := stats["intl.timeZone"]; st.Total != 3 || st.Count != 3 || st.Bits != 0 {
		t.Fatalf("time zone stat = %+v", st)
	}
	if st := stats["canvas.2d"]; st.Count != 1 || st.Bits != 1.58 {
		t.Fatalf("canvas stat = %+v", st)
	}
}

func TestScanRejectsBadInput(t *testing.T) {
	h := testServer(t)
	for _, body := range []string{"", "{", `{"signals":{}}`, strings.Repeat("x", 600<<10)} {
		req := httptest.NewRequest(http.MethodPost, "https://whoami.test/api/scan", strings.NewReader(body))
		req.RemoteAddr = "192.0.2.20:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body of %d bytes: status %d", len(body), rec.Code)
		}
	}
}

func TestScanRateLimit(t *testing.T) {
	h := testServer(t)
	limited := false
	for range 14 {
		if doScan(t, h, chromeUA, chromeSignals(), nil).status == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("14 scans in a row were all accepted")
	}
}

func TestPagesAndHeaders(t *testing.T) {
	h := testServer(t)
	get := func(url, accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Accept", accept)
		req.RemoteAddr = "192.0.2.30:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	page := get("https://whoami.test/", "text/html,application/xhtml+xml")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `id="scan"`) || !strings.Contains(page.Body.String(), "192.0.2.30") {
		t.Fatalf("index: %d", page.Code)
	}
	for _, hdr := range []string{"Content-Security-Policy", "Strict-Transport-Security", "Accept-CH"} {
		if page.Header().Get(hdr) == "" {
			t.Errorf("index lacks %s", hdr)
		}
	}

	text := get("https://whoami.test/", "*/*")
	if !strings.HasPrefix(text.Header().Get("Content-Type"), "text/plain") || !strings.Contains(text.Body.String(), "IP address") {
		t.Fatalf("curl view: %s", text.Body.String())
	}
	if code := get("https://other.test/", "*/*").Code; code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host: %d", code)
	}
	if code := get("https://whoami.test/static/app.js", "*/*").Code; code != 200 {
		t.Fatalf("static: %d", code)
	}
	if body := get("https://whoami.test/healthz", "*/*").Body.String(); body != "ok\n" {
		t.Fatalf("healthz: %q", body)
	}
}

// Every attribute the server expects must be collected by the page, and
// everything the page sends must be registered (or it is silently dropped).
func TestRegistryMatchesCollector(t *testing.T) {
	src, err := fs.ReadFile(webFS, "web/static/collect.js")
	if err != nil {
		t.Fatal(err)
	}
	sent := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:set\(|signals\[)"([a-z0-9]+\.[A-Za-z0-9]+)"`).FindAllStringSubmatch(string(src), -1) {
		sent[m[1]] = true
	}
	registered := map[string]bool{}
	for _, a := range attrs {
		if registered[a.Key] {
			t.Errorf("attribute %s registered twice", a.Key)
		}
		registered[a.Key] = true
		if !a.Server && !sent[a.Key] {
			t.Errorf("attribute %s is registered but the page never sends it", a.Key)
		}
		if a.Device && !a.Browser {
			t.Errorf("device attribute %s should also be part of the browser identity", a.Key)
		}
	}
	for _, k := range slicesSorted(sent) {
		if !registered[k] {
			t.Errorf("the page sends %s, which the server does not know", k)
		}
	}
	groups := map[string]bool{}
	for _, g := range groups_() {
		groups[g] = true
	}
	for _, a := range attrs {
		if !groups[a.Group] {
			t.Errorf("attribute %s is in unknown group %s", a.Key, a.Group)
		}
	}
}

func slicesSorted(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range maps.Keys(m) {
		keys = append(keys, k)
	}
	return keys
}

func groups_() []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.ID
	}
	return out
}

func TestStabilize(t *testing.T) {
	in := json.RawMessage(`{"fullVersionList":["Google Chrome 141.0.7390.55","Not_A Brand 8.0.0.0"],"platformVersion":"15.0.0","model":""}`)
	got := string(stabilize("uach.highEntropy", in))
	want := `{"fullVersionList":["Google Chrome 141","Not_A Brand 8"],"model":"","platformVersion":"15"}`
	if got != want {
		t.Fatalf("stabilize = %s", got)
	}
	if string(stabilize("canvas.2d", json.RawMessage(`"x"`))) != `"x"` {
		t.Fatal("other attributes must pass through unchanged")
	}
}
