package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"whoami/internal/persona"
	"whoami/internal/store"
)

const cookieName = "whoami_id"

type scanRequest struct {
	Signals map[string]json.RawMessage `json:"signals"`
	Noise   struct {
		Canvas       bool `json:"canvas"`       // differs on every read
		CanvasExport bool `json:"canvasExport"` // exported images differ from the drawn pixels
		Audio        bool `json:"audio"`
	} `json:"noise"`
	FingerprintJS *struct {
		VisitorID  string  `json:"visitorId"`
		Confidence float64 `json:"confidence"`
	} `json:"fingerprintjs"`
}

type attrStat struct {
	Key     string  `json:"key"`
	Count   uint32  `json:"count,omitempty"`
	Total   int     `json:"total,omitempty"`
	Bits    float64 `json:"bits,omitempty"`
	Value   string  `json:"value,omitempty"` // only for values the server observed
	Present bool    `json:"present"`
}

type sibling struct {
	Persona  persona.Persona `json:"persona"`
	Label    string          `json:"label"`
	LastSeen time.Time       `json:"lastSeen"`
}

type scanResponse struct {
	Issued        time.Time `json:"issued"`
	RetentionDays int       `json:"retentionDays"`
	UA            struct {
		userAgent
		Label string `json:"label"`
	} `json:"ua"`
	Browser struct {
		ID        string          `json:"id"`
		Persona   persona.Persona `json:"persona"`
		MRZ       [2]string       `json:"mrz"`
		Seen      bool            `json:"seen"`
		FirstSeen time.Time       `json:"firstSeen"`
		Expires   time.Time       `json:"expires"`
		Visits    uint32          `json:"visits"`
		People    int             `json:"people"`
		Total     int             `json:"total"`
	} `json:"browser"`
	Device struct {
		Persona  persona.Persona `json:"persona"`
		Matches  int             `json:"matches"`
		Siblings []sibling       `json:"siblings"`
	} `json:"device"`
	Network struct {
		Persona persona.Persona `json:"persona"`
	} `json:"network"`
	Cookie struct {
		Persona   persona.Persona `json:"persona"`
		Status    string          `json:"status"` // new, returning, moved
		FirstSeen time.Time       `json:"firstSeen"`
	} `json:"cookie"`
	FingerprintJS *struct {
		Persona   persona.Persona `json:"persona"`
		VisitorID string          `json:"visitorId"`
	} `json:"fingerprintjs"`
	RecognizedWithoutCookie bool       `json:"recognizedWithoutCookie"`
	Groups                  any        `json:"groups"`
	Attributes              []attr     `json:"attributes"`
	Stats                   []attrStat `json:"stats"`
	Checks                  []check    `json:"checks"`
	Server                  serverView `json:"server"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func errorJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// gpuVendor reduces the WebGL vendor/renderer strings to the maker, which is
// what stays the same across browsers on one machine (each browser words the
// renderer differently).
func gpuVendor(canon string) string {
	s := strings.ToLower(canon)
	for _, v := range []struct{ word, name string }{
		{"swiftshader", "software"}, {"llvmpipe", "software"}, {"lavapipe", "software"},
		{"softpipe", "software"}, {"basic render", "software"},
		{"apple", "apple"}, {"nvidia", "nvidia"}, {"geforce", "nvidia"}, {"radeon", "amd"},
		{"amd", "amd"}, {"intel", "intel"}, {"adreno", "qualcomm"}, {"qualcomm", "qualcomm"},
		{"mali", "arm"}, {"powervr", "imagination"}, {"imagination", "imagination"},
	} {
		if strings.Contains(s, v.word) {
			return v.name
		}
	}
	if canon == missing {
		return missing
	}
	return "other"
}

func primaryLanguage(canon string) string {
	var langs []string
	if json.Unmarshal([]byte(canon), &langs) != nil || len(langs) == 0 {
		return missing
	}
	return strings.ToLower(langs[0])
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	ip := clientAddr(r)
	if !s.scans.allow(ip, now) {
		errorJSON(w, http.StatusTooManyRequests, "Too many scans from your address. Wait a minute and try again.")
		return
	}
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "The scan data could not be read.")
		return
	}
	if len(req.Signals) == 0 {
		errorJSON(w, http.StatusBadRequest, "The scan sent no signals.")
		return
	}

	// Reverse DNS can take a moment; start it alongside the rest.
	viewc := make(chan serverView, 1)
	go func() { viewc <- s.view(r.Context(), r, true) }()

	// Server-observed values.
	conn := connFrom(r)
	server := map[string]string{
		"http.acceptLanguage": canonicalString(r.Header.Get("Accept-Language")),
		"http.acceptEncoding": canonicalString(r.Header.Get("Accept-Encoding")),
		"tls.ja4":             missing,
		"h2.akamai":           canonicalString("not HTTP/2"),
		"http.headerOrder":    missing,
	}
	tlsFamily, h2Family := "", ""
	if conn != nil {
		if h, err := conn.ClientHello(); err == nil && h != nil {
			ja4, _ := h.JA4()
			server["tls.ja4"] = canonicalString(ja4)
			tlsFamily = h.Family()
		}
		if f := conn.H2(); f != nil {
			server["h2.akamai"] = canonicalString(f.Akamai())
			h2Family = f.Family()
		}
		if order := conn.FirstRequestHeaderOrder(); len(order) > 0 {
			server["http.headerOrder"] = canonicalString(strings.Join(order, ","))
		}
	}

	// Canonical value of every attribute, in registry order.
	values := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if a.Server {
			values[a.Key] = server[a.Key]
		} else {
			values[a.Key] = canonical(stabilize(a.Key, req.Signals[a.Key]))
		}
	}
	// A canvas or audio reading that changes on every read can't identify
	// anyone; replace it with a marker so the rest of the fingerprint stays
	// comparable, as a real tracker would.
	if req.Noise.Canvas {
		values["canvas.2d"] = canonicalString("randomized")
	}
	if req.Noise.Audio {
		values["audio.fingerprint"] = canonicalString("randomized")
	}

	var hints *clientHints
	if raw, ok := req.Signals["uach.highEntropy"]; ok && string(raw) != "null" {
		hints = &clientHints{}
		if json.Unmarshal(raw, hints) != nil {
			hints = nil
		}
	}
	if hints == nil {
		if raw, ok := req.Signals["uach.brands"]; ok && string(raw) != "null" {
			hints = &clientHints{}
			if json.Unmarshal(raw, hints) != nil {
				hints = nil
			}
		}
	}
	uaString := r.UserAgent()
	ua := parseUA(uaString)
	ua.refine(hints)

	// Identities.
	var browserCanon, deviceCanon strings.Builder
	var attrHashes []uint64
	for _, a := range attrs {
		if a.Browser {
			browserCanon.WriteString(a.Key + "=" + values[a.Key] + "\n")
			attrHashes = append(attrHashes, s.keys.short("attr", a.Key, values[a.Key]))
		}
		if a.Device {
			deviceCanon.WriteString(a.Key + "=" + values[a.Key] + "\n")
		}
	}
	deviceCanon.WriteString("os=" + ua.OS + "\n")
	deviceCanon.WriteString("gpu=" + gpuVendor(values["gpu.webgl"]) + "\n")
	deviceCanon.WriteString("lang=" + primaryLanguage(values["nav.languages"]) + "\n")
	browserID := s.keys.id("browser", browserCanon.String())
	deviceID := s.keys.id("device", deviceCanon.String())
	networkID := s.keys.id("network", ip.String())

	// The cookie: a random first-party identifier, the oldest tracking tool.
	cookieStatus := "new"
	var raw [16]byte
	if c, err := r.Cookie(cookieName); err == nil {
		if b, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil && len(b) == 16 {
			copy(raw[:], b)
			cookieStatus = "returning"
		}
	}
	if cookieStatus == "new" {
		_, _ = rand.Read(raw[:])
	}
	cookieKey := s.keys.id("cookie", string(raw[:]))
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: base64.RawURLEncoding.EncodeToString(raw[:]), Path: "/",
		MaxAge: s.cfg.RetentionDays * 86400, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})

	res := s.store.Observe(store.Observation{
		Browser: browserID, Device: deviceID, Network: s.keys.short("network", ip.String()),
		Label: ua.label(), Attrs: attrHashes, Cookie: &cookieKey, Now: now,
	})
	if cookieStatus == "returning" && !res.CookieSeen {
		cookieStatus = "new" // a cookie we no longer know (expired or forgotten)
	}
	if res.CookieMoved {
		cookieStatus = "moved"
	}

	var out scanResponse
	out.Issued = now.UTC()
	out.RetentionDays = s.cfg.RetentionDays
	out.UA.userAgent, out.UA.Label = ua, ua.label()

	out.Browser.ID = hex.EncodeToString(browserID[:])
	out.Browser.Persona = persona.From(browserID)
	out.Browser.Seen = res.Seen
	out.Browser.FirstSeen = res.First.UTC()
	out.Browser.Expires = now.AddDate(0, 0, s.cfg.RetentionDays).UTC()
	out.Browser.Visits = res.Visits
	out.Browser.People = max(res.People, 1)
	out.Browser.Total = res.Total
	out.Browser.MRZ = persona.MRZ(out.Browser.Persona, browserID, deviceID, res.First, out.Browser.Expires)

	out.Device.Persona = persona.From(deviceID)
	out.Device.Matches = res.DeviceMatches
	out.Device.Siblings = []sibling{}
	for _, sib := range res.Siblings {
		out.Device.Siblings = append(out.Device.Siblings, sibling{Persona: persona.From(sib.Browser), Label: sib.Label, LastSeen: sib.Last.UTC()})
	}
	out.Network.Persona = persona.From(networkID)
	out.Cookie.Persona = persona.From(cookieKey)
	out.Cookie.Status = cookieStatus
	out.Cookie.FirstSeen = res.CookieFirst.UTC()
	if f := req.FingerprintJS; f != nil && len(f.VisitorID) >= 8 && len(f.VisitorID) <= 64 {
		id := s.keys.id("fingerprintjs", f.VisitorID)
		out.FingerprintJS = &struct {
			Persona   persona.Persona `json:"persona"`
			VisitorID string          `json:"visitorId"`
		}{persona.From(id), f.VisitorID}
	}
	out.RecognizedWithoutCookie = res.Seen && cookieStatus == "new"

	out.Groups = groups
	out.Attributes = attrs
	hashIdx := 0
	for _, a := range attrs {
		st := attrStat{Key: a.Key, Present: values[a.Key] != missing}
		if a.Browser {
			st.Count, st.Total = res.AttrCounts[hashIdx], res.Total
			if st.Count > 0 && res.Total > 0 {
				st.Bits = math.Round(math.Log2(float64(res.Total)/float64(st.Count))*100) / 100
			}
			hashIdx++
		}
		if a.Server && values[a.Key] != missing {
			st.Value = display(values[a.Key])
		}
		out.Stats = append(out.Stats, st)
	}

	select {
	case out.Server = <-viewc:
	case <-time.After(3 * time.Second):
		out.Server = s.view(context.Background(), r, false)
	}

	var langs []string
	_ = json.Unmarshal(req.Signals["nav.languages"], &langs)
	var tz, platform string
	_ = json.Unmarshal(req.Signals["intl.timeZone"], &tz)
	_ = json.Unmarshal(req.Signals["nav.platform"], &platform)
	var webdriver bool
	_ = json.Unmarshal(req.Signals["nav.webdriver"], &webdriver)
	var privacy struct {
		GPC bool `json:"gpc"`
	}
	_ = json.Unmarshal(req.Signals["privacy.signals"], &privacy)
	var adblock bool
	_ = json.Unmarshal(req.Signals["privacy.adblock"], &adblock)
	out.Checks = runChecks(checkInput{
		ua: ua, uaString: uaString, hints: hints, platform: platform, languages: langs,
		acceptLanguage: r.Header.Get("Accept-Language"), timeZone: tz, webdriver: webdriver,
		tlsFamily: tlsFamily, h2Family: h2Family,
		location: out.Server.IP.Location, network: out.Server.IP.Network,
		tor: out.Server.IP.Tor, hosting: out.Server.IP.Hosting,
		canvasNoise: req.Noise.Canvas, canvasExportNoise: req.Noise.CanvasExport, audioNoise: req.Noise.Audio,
		gpc: privacy.GPC || r.Header.Get("Sec-GPC") == "1", adblock: adblock, now: now,
	})
	writeJSON(w, http.StatusOK, out)
}

type forgetRequest struct {
	Browser string `json:"browser"`
}

func (s *server) handleForget(w http.ResponseWriter, r *http.Request) {
	if !s.forgets.allow(clientAddr(r), time.Now()) {
		errorJSON(w, http.StatusTooManyRequests, "Too many requests. Wait a minute and try again.")
		return
	}
	var req forgetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	b, err := hex.DecodeString(req.Browser)
	if err != nil || len(b) != 16 {
		errorJSON(w, http.StatusBadRequest, "That is not a browser ID from this site.")
		return
	}
	var cookieKey *store.ID
	if c, err := r.Cookie(cookieName); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil && len(raw) == 16 {
			k := s.keys.id("cookie", string(raw))
			cookieKey = &k
		}
	}
	forgotten := s.store.Forget(store.ID(b), cookieKey)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if err := s.store.Save(); err != nil && !errors.Is(err, context.Canceled) {
		errorJSON(w, http.StatusInternalServerError, "Forgotten in memory, but saving failed; it will be retried.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"forgotten": forgotten})
}
