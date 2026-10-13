package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// attr describes one fingerprint attribute. Browser marks attributes that make
// up the browser identity; Device marks the subset of system-level ones that
// usually stay the same in every browser on the same computer. Attributes in
// neither set are shown but never stored, because they change too often
// (window size, network speed) or would make the ID needlessly unstable.
type attr struct {
	Key     string `json:"key"`
	Group   string `json:"group"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Browser bool   `json:"browser"`
	Device  bool   `json:"device"`
	Server  bool   `json:"server"` // observed by the server rather than reported by the page
}

var groups = []struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}{
	{"server", "Seen before any script runs"},
	{"browser", "Browser and system"},
	{"locale", "Language and time"},
	{"display", "Screen and display"},
	{"hardware", "Hardware"},
	{"render", "Drawing, sound and fonts"},
	{"privacy", "Storage and privacy settings"},
	{"volatile", "Changes too often to track you"},
}

var attrs = []attr{
	{Key: "tls.ja4", Group: "server", Label: "TLS fingerprint (JA4)", Browser: true, Server: true,
		Help: "How your browser opens an encrypted connection: the ciphers and extensions it offers. Each browser engine has its own pattern, visible to any server or network in between."},
	{Key: "h2.akamai", Group: "server", Label: "HTTP/2 fingerprint", Browser: true, Server: true,
		Help: "The settings your browser sends when it starts an HTTP/2 connection. Bot-detection services compare it with the browser you claim to be."},
	{Key: "http.acceptLanguage", Group: "server", Label: "Accept-Language header", Browser: true, Server: true,
		Help: "Your preferred languages, sent with every request to every site."},
	{Key: "http.acceptEncoding", Group: "server", Label: "Accept-Encoding header", Browser: true, Server: true,
		Help: "The compression formats your browser supports."},
	{Key: "http.headerOrder", Group: "server", Label: "Header order", Server: true,
		Help: "The order HTTP/1.1 headers arrived in. Libraries and browsers each have their own."},

	{Key: "nav.userAgent", Group: "browser", Label: "User-Agent", Browser: true,
		Help: "Your browser's name and version and your operating system, sent with every request."},
	{Key: "uach.brands", Group: "browser", Label: "Client hints", Browser: true,
		Help: "A structured User-Agent that Chromium-based browsers expose. Brave, Edge and Opera name themselves here even when their User-Agent says Chrome."},
	{Key: "uach.highEntropy", Group: "browser", Label: "Detailed client hints", Browser: true,
		Help: "Exact browser build, OS version, CPU architecture and device model. Chromium hands these to any script that asks."},
	{Key: "nav.platform", Group: "browser", Label: "Platform", Browser: true,
		Help: "The operating system as reported to scripts."},
	{Key: "nav.engine", Group: "browser", Label: "Engine details", Browser: true,
		Help: "Small strings that differ between browser engines, such as the vendor name and product number."},
	{Key: "js.features", Group: "browser", Label: "Supported features", Browser: true,
		Help: "Which recent web platform features exist. The combination pins down your browser version."},
	{Key: "js.math", Group: "browser", Label: "Math results", Browser: true,
		Help: "Results of floating-point functions like tan and sinh, which differ in the last digits between engines and systems."},
	{Key: "nav.plugins", Group: "browser", Label: "Plugins", Browser: true,
		Help: "Plugins the browser lists. Modern browsers report the same built-in PDF viewers; old ones leak much more."},
	{Key: "nav.webdriver", Group: "browser", Label: "Automation flag", Browser: true,
		Help: "Set when the browser is driven by automation software such as Selenium or Playwright."},

	{Key: "intl.timeZone", Group: "locale", Label: "Time zone", Browser: true, Device: true,
		Help: "Your system's time zone. Compared with your IP address it reveals VPN use."},
	{Key: "nav.languages", Group: "locale", Label: "Languages", Browser: true,
		Help: "The languages your browser prefers, in order."},
	{Key: "intl.locale", Group: "locale", Label: "Regional settings", Browser: true,
		Help: "Locale, calendar, numbering system and 12- or 24-hour clock."},
	{Key: "intl.formats", Group: "locale", Label: "Date and number formatting", Browser: true,
		Help: "How a fixed date and number look when formatted on your system."},
	{Key: "keyboard.layout", Group: "locale", Label: "Keyboard layout", Browser: true,
		Help: "What a few keys produce on your keyboard (QWERTY, AZERTY, QWERTZ...). Only Chromium exposes this."},

	{Key: "screen.size", Group: "display", Label: "Screen resolution", Browser: true, Device: true,
		Help: "Width and height of your screen in CSS pixels."},
	{Key: "screen.avail", Group: "display", Label: "Available screen area", Browser: true,
		Help: "Your screen minus taskbars and docks, which depends on your desktop layout."},
	{Key: "screen.colorDepth", Group: "display", Label: "Color depth", Browser: true, Device: true,
		Help: "Bits per pixel your display reports."},
	{Key: "css.media", Group: "display", Label: "Display preferences", Browser: true,
		Help: "Reduced motion, contrast, color gamut, HDR and pointer type, as CSS sees them."},

	{Key: "hw.cores", Group: "hardware", Label: "CPU threads", Browser: true, Device: true,
		Help: "Number of logical processors."},
	{Key: "hw.memory", Group: "hardware", Label: "Device memory", Browser: true,
		Help: "Approximate RAM in GB, rounded. Chromium only."},
	{Key: "hw.touch", Group: "hardware", Label: "Touch support", Browser: true, Device: true,
		Help: "How many touch points the screen supports."},
	{Key: "gpu.webgl", Group: "hardware", Label: "Graphics card", Browser: true,
		Help: "The GPU and driver named through WebGL."},
	{Key: "gpu.webglParams", Group: "hardware", Label: "Graphics capabilities", Browser: true,
		Help: "Limits, extensions and shader precision of your graphics stack."},
	{Key: "gpu.webgpu", Group: "hardware", Label: "WebGPU adapter", Browser: true,
		Help: "GPU vendor and architecture through the newer WebGPU interface."},
	{Key: "speech.voices", Group: "hardware", Label: "Speech voices", Browser: true,
		Help: "Text-to-speech voices installed on your system, which depend on OS, region and language packs."},
	{Key: "audio.context", Group: "hardware", Label: "Audio output", Browser: true,
		Help: "Sample rate and channel count of your audio device."},

	{Key: "canvas.2d", Group: "render", Label: "Canvas drawing", Browser: true,
		Help: "A hidden drawing of text, emoji and shapes. Fonts, anti-aliasing and the GPU change the exact pixels."},
	{Key: "gpu.webglRender", Group: "render", Label: "WebGL drawing", Browser: true,
		Help: "A small 3D scene drawn by your graphics card and read back pixel by pixel."},
	{Key: "audio.fingerprint", Group: "render", Label: "Audio processing", Browser: true,
		Help: "A short tone processed by your browser's audio engine, measured without playing anything."},
	{Key: "fonts.installed", Group: "render", Label: "Installed fonts", Browser: true,
		Help: "Which of about a hundred common fonts are present, detected by measuring text."},
	{Key: "fonts.emoji", Group: "render", Label: "Emoji rendering", Browser: true,
		Help: "The size of drawn emoji, which reveals your system's emoji font version."},

	{Key: "storage.available", Group: "privacy", Label: "Storage access", Browser: true,
		Help: "Whether cookies, local storage and IndexedDB work."},
	{Key: "privacy.signals", Group: "privacy", Label: "Do Not Track and GPC", Browser: true,
		Help: "Opt-out signals your browser sends. Rare settings make you more identifiable, not less."},
	{Key: "privacy.adblock", Group: "privacy", Label: "Ad blocker", Browser: true,
		Help: "Whether elements that look like ads get hidden, the same check sites use to show \"please disable your ad blocker\"."},
	{Key: "timing.resolution", Group: "privacy", Label: "Timer precision", Browser: true,
		Help: "How finely scripts can measure time. Privacy-focused browsers make it coarser."},

	{Key: "window.size", Group: "volatile", Label: "Window size",
		Help: "Changes whenever you resize the window."},
	{Key: "screen.dpr", Group: "volatile", Label: "Pixel ratio",
		Help: "Device pixels per CSS pixel: display scaling times page zoom, so it changes when you zoom."},
	{Key: "css.colorScheme", Group: "volatile", Label: "Light or dark theme",
		Help: "Follows your system setting, which many people let switch automatically at night."},
	{Key: "media.devices", Group: "volatile", Label: "Cameras, microphones, speakers",
		Help: "How many of each are connected: it changes when you plug in a headset. Names stay hidden until you grant permission."},
	{Key: "net.connection", Group: "volatile", Label: "Connection estimate",
		Help: "Effective type, round-trip time and bandwidth estimate (Chromium only)."},
	{Key: "storage.quota", Group: "volatile", Label: "Storage quota",
		Help: "How much the site may store, which depends on free disk space."},
	{Key: "perms.states", Group: "volatile", Label: "Permissions",
		Help: "Which permissions this site has been granted or denied. Checking them shows no prompt."},
}

var attrByKey = func() map[string]*attr {
	m := make(map[string]*attr, len(attrs))
	for i := range attrs {
		m[attrs[i].Key] = &attrs[i]
	}
	return m
}()

const missing = "<missing>"

// canonical turns a JSON value into a stable string: object keys sorted,
// numbers kept exactly as sent. Oversized values are rejected rather than
// truncated so two different large values never collide.
func canonical(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return missing
	}
	if len(raw) > 32<<10 {
		return "<oversized>"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "<invalid>"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "<invalid>"
	}
	return string(b)
}

// stabilize drops the parts of a value that change on routine updates, so
// the identity survives them the way a tracker's would: exact Chromium
// builds (weekly) and OS point releases become major versions.
func stabilize(key string, raw json.RawMessage) json.RawMessage {
	if key != "uach.highEntropy" || len(raw) == 0 || string(raw) == "null" {
		return raw
	}
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	if list, ok := v["fullVersionList"].([]any); ok {
		for i, e := range list {
			if s, ok := e.(string); ok {
				if j := strings.LastIndexByte(s, ' '); j > 0 {
					major, _, _ := strings.Cut(s[j+1:], ".")
					list[i] = s[:j+1] + major
				}
			}
		}
	}
	if pv, ok := v["platformVersion"].(string); ok {
		v["platformVersion"], _, _ = strings.Cut(pv, ".")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// canonicalString is canonical for a value the server observed itself.
func canonicalString(s string) string {
	if s == "" {
		return missing
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// display renders a canonical value for people: lists become comma
// separated, objects "key: value" pairs. Long values are shortened.
func display(canon string) string {
	if canon == missing {
		return "Not available"
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(canon))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return shorten(canon, 280)
	}
	return shorten(render(v), 280)
}

func render(v any) string {
	switch x := v.(type) {
	case nil:
		return "none"
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case string:
		return x
	case json.Number:
		return x.String()
	case []any:
		if len(x) == 0 {
			return "none"
		}
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = render(e)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := sortedKeys(x)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+": "+render(x[k]))
		}
		return strings.Join(parts, "; ")
	}
	return ""
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
