package main

import (
	"regexp"
	"strconv"
	"strings"
)

// userAgent is the browser and system a client claims to be, from the
// User-Agent string refined by User-Agent Client Hints when available.
type userAgent struct {
	Browser   string `json:"browser"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
	Mobile    bool   `json:"mobile"`
	Tool      bool   `json:"tool"` // curl, scripts, libraries
}

var (
	reVersion = func(token string) *regexp.Regexp {
		return regexp.MustCompile(regexp.QuoteMeta(token) + `/(\d+(?:\.\d+)*)`)
	}
	uaBrowsers = []struct {
		name  string
		re    *regexp.Regexp
		other bool
	}{
		{"Edge", reVersion("Edg"), false},
		{"Edge", reVersion("EdgA"), false},
		{"Edge", reVersion("EdgiOS"), false},
		{"Opera", reVersion("OPR"), false},
		{"Samsung Internet", reVersion("SamsungBrowser"), false},
		{"Yandex Browser", reVersion("YaBrowser"), false},
		{"Vivaldi", reVersion("Vivaldi"), false},
		{"Chrome", reVersion("CriOS"), false},
		{"Firefox", reVersion("FxiOS"), false},
		{"Firefox", reVersion("Firefox"), false},
		{"Headless Chrome", reVersion("HeadlessChrome"), false},
		{"Chrome", reVersion("Chrome"), false},
		{"curl", reVersion("curl"), true},
		{"Wget", reVersion("Wget"), true},
		{"Python", reVersion("python-requests"), true},
		{"Python", reVersion("python-httpx"), true},
		{"Python", reVersion("Python-urllib"), true},
		{"Go", reVersion("Go-http-client"), true},
		{"Node.js", reVersion("node-fetch"), true},
		{"OkHttp", reVersion("okhttp"), true},
		{"HTTPie", reVersion("HTTPie"), true},
	}
	reSafari  = regexp.MustCompile(`Version/(\d+(?:\.\d+)*).*Safari/`)
	reWindows = regexp.MustCompile(`Windows NT (\d+\.\d+)`)
	reMac     = regexp.MustCompile(`Mac OS X (\d+[._]\d+(?:[._]\d+)?)`)
	reIOS     = regexp.MustCompile(`(?:iPhone|CPU) OS (\d+(?:_\d+)*)`)
	reAndroid = regexp.MustCompile(`Android (\d+(?:\.\d+)*)`)
)

func parseUA(ua string) userAgent {
	var u userAgent
	for _, b := range uaBrowsers {
		if m := b.re.FindStringSubmatch(ua); m != nil {
			u.Browser, u.Version, u.Tool = b.name, m[1], b.other
			break
		}
	}
	if u.Browser == "" {
		if m := reSafari.FindStringSubmatch(ua); m != nil && strings.Contains(ua, "AppleWebKit") {
			u.Browser, u.Version = "Safari", m[1]
		}
	}
	switch {
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod"):
		u.OS = "iOS"
		if strings.Contains(ua, "iPad") {
			u.OS = "iPadOS"
		}
		if m := reIOS.FindStringSubmatch(ua); m != nil {
			u.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
		u.Mobile = true
	case strings.Contains(ua, "Android"):
		u.OS = "Android"
		if m := reAndroid.FindStringSubmatch(ua); m != nil {
			u.OSVersion = m[1]
		}
		u.Mobile = strings.Contains(ua, "Mobile")
	case strings.Contains(ua, "Windows"):
		u.OS = "Windows"
		if m := reWindows.FindStringSubmatch(ua); m != nil {
			u.OSVersion = map[string]string{"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7"}[m[1]]
		}
	case strings.Contains(ua, "CrOS"):
		u.OS = "ChromeOS"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		u.OS = "macOS"
		if m := reMac.FindStringSubmatch(ua); m != nil {
			u.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	case strings.Contains(ua, "Linux"):
		u.OS = "Linux"
	}
	return u
}

// clientHints is the subset of navigator.userAgentData the page reports.
type clientHints struct {
	Brands          []string `json:"brands"`
	Mobile          bool     `json:"mobile"`
	Platform        string   `json:"platform"`
	PlatformVersion string   `json:"platformVersion"`
	FullVersionList []string `json:"fullVersionList"`
	Architecture    string   `json:"architecture"`
	Model           string   `json:"model"`
}

// refine improves the parse with client hints: they name Brave, Edge and
// Opera even when the UA string says Chrome, and carry real OS versions that
// the frozen UA string no longer does.
func (u *userAgent) refine(ch *clientHints) {
	if ch == nil {
		return
	}
	// Entries look like "Google Chrome 141.0.7390.55"; the full version list
	// comes first so its precise versions win.
	brands := append(append([]string(nil), ch.FullVersionList...), ch.Brands...)
found:
	for _, want := range []struct{ brand, name string }{
		{"Brave", "Brave"}, {"Microsoft Edge", "Edge"}, {"Opera", "Opera"},
		{"Vivaldi", "Vivaldi"}, {"Google Chrome", "Chrome"}, {"Chromium", "Chromium"},
	} {
		for _, b := range brands {
			i := strings.LastIndexByte(b, ' ')
			if i <= 0 || b[:i] != want.brand {
				continue
			}
			if u.Browser == "" || u.Browser == "Chrome" || u.Browser == "Chromium" {
				u.Browser = want.name
			}
			if u.Browser == want.name && len(b[i+1:]) > len(u.Version) {
				u.Version = b[i+1:]
			}
			break found
		}
	}
	switch ch.Platform {
	case "Windows":
		u.OS = "Windows"
		if major, err := strconv.Atoi(strings.Split(ch.PlatformVersion, ".")[0]); err == nil && ch.PlatformVersion != "" {
			if major >= 13 {
				u.OSVersion = "11"
			} else if major > 0 {
				u.OSVersion = "10"
			}
		}
	case "macOS", "Android", "Chrome OS", "ChromeOS", "Linux", "iOS":
		if ch.Platform == "Chrome OS" {
			u.OS = "ChromeOS"
		} else {
			u.OS = ch.Platform
		}
		if ch.PlatformVersion != "" && ch.Platform != "Linux" {
			u.OSVersion = strings.TrimSuffix(ch.PlatformVersion, ".0")
		}
	}
	u.Mobile = u.Mobile || ch.Mobile
}

// family groups browsers by network stack, for comparison with the TLS and
// HTTP/2 fingerprints.
func (u userAgent) family() string {
	switch {
	case u.Tool:
		return "tool"
	case u.OS == "iOS" || u.OS == "iPadOS" || u.Browser == "Safari":
		return "apple" // every iOS browser uses Apple's network stack
	case u.Browser == "Firefox":
		return "firefox"
	case u.Browser != "":
		return "chromium"
	}
	return "unknown"
}

// label is a coarse description: browser, major version, OS.
func (u userAgent) label() string {
	b := u.Browser
	if b == "" {
		b = "Unknown browser"
	}
	if major, _, _ := strings.Cut(u.Version, "."); major != "" {
		b += " " + major
	}
	if u.OS != "" {
		b += " on " + u.OS
		if u.OSVersion != "" {
			b += " " + u.OSVersion
		}
	}
	return b
}
