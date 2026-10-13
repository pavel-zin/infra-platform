package main

import (
	"fmt"
	"strings"
	"time"

	"whoami/internal/geo"
	"whoami/internal/netfp"
)

// check is one of the consistency tests bot-detection and fraud-prevention
// services run: does everything a browser reveals tell the same story?
type check struct {
	ID     string `json:"id"`
	Status string `json:"status"` // "ok", "warn" or "info"
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type checkInput struct {
	ua                userAgent
	uaString          string
	hints             *clientHints
	platform          string
	languages         []string
	acceptLanguage    string
	timeZone          string
	webdriver         bool
	tlsFamily         string
	h2Family          string
	location          geo.Location
	network           geo.Network
	tor, hosting      bool
	canvasNoise       bool
	canvasExportNoise bool
	audioNoise        bool
	gpc               bool
	adblock           bool
	now               time.Time
}

func familyLabel(f string) string {
	switch f {
	case "chromium":
		return "a Chromium-based browser"
	case "firefox":
		return "Firefox"
	case "apple":
		return "Safari or another browser on Apple's network stack"
	case "tool":
		return "a command-line tool or script"
	}
	return f
}

func runChecks(in checkInput) []check {
	var out []check
	add := func(id, status, title, detail string, args ...any) {
		out = append(out, check{ID: id, Status: status, Title: title, Detail: fmt.Sprintf(detail, args...)})
	}
	uaFam := in.ua.family()
	claimed := in.ua.Browser
	if claimed == "" {
		claimed = "an unknown browser"
	}

	// 1. User-Agent against the TLS handshake.
	if tf := in.tlsFamily; tf != "" && tf != "unknown" && uaFam != "unknown" {
		tlsName := netfp.FamilyName(tf)
		switch {
		case uaFam == "tool" || tf == "openssl" || tf == "go":
			add("ua-tls", "info", "Your handshake says you're a script, not a browser",
				"The TLS handshake looks like a %s. Sites that only want browsers can refuse you before reading a single header.", tlsName)
		case uaFam == tf:
			add("ua-tls", "ok", "Your TLS handshake matches your browser",
				"The User-Agent says %s and the handshake looks like %s. That also means the handshake alone, before any script runs, tells a site which browser family you use.", claimed, tlsName)
		default:
			add("ua-tls", "warn", "Your browser's claims don't match its TLS handshake",
				"The User-Agent says %s, but the handshake looks like %s. Bot-detection services block exactly this mismatch; it usually means a spoofed User-Agent or an automation tool.", claimed, tlsName)
		}
	}

	// 2. User-Agent against the HTTP/2 fingerprint.
	if hf := in.h2Family; hf != "" && hf != "unknown" && uaFam != "unknown" && uaFam != "tool" {
		switch {
		case hf == uaFam:
			add("ua-h2", "ok", "Your HTTP/2 settings match your browser",
				"The way your browser opened the HTTP/2 connection is typical of %s.", familyLabel(hf))
		case hf == "nghttp2" || hf == "go":
			add("ua-h2", "warn", "Your HTTP/2 settings belong to a library, not a browser",
				"The connection was opened like %s would open it, while the User-Agent claims %s.", netfp.FamilyName(hf), claimed)
		default:
			add("ua-h2", "warn", "Your HTTP/2 settings don't match your browser",
				"The User-Agent says %s, but the HTTP/2 connection was opened the way %s does it.", claimed, familyLabel(hf))
		}
	}

	// 3. Client hints against the User-Agent string.
	if in.hints != nil && len(in.hints.Brands) > 0 && (uaFam == "firefox" || uaFam == "apple") {
		add("uach", "warn", "Your User-Agent was rewritten",
			"Your browser exposes Chromium's client hints (%s), but its User-Agent claims %s.", strings.Join(in.hints.Brands, ", "), claimed)
	} else if in.hints == nil && uaFam == "chromium" && !in.ua.Mobile && strings.HasPrefix(in.ua.Browser, "Chrome") && majorVersion(in.ua.Version) >= 90 {
		add("uach", "warn", "Your User-Agent claims Chrome, but the browser isn't",
			"Every desktop Chrome since version 89 exposes client hints. This browser does not, so the Chrome User-Agent is probably borrowed.")
	}

	// 4. navigator.platform against the operating system in the User-Agent.
	if p := in.platform; p != "" && in.ua.OS != "" {
		want := map[string][]string{
			"Windows":  {"Win"},
			"macOS":    {"Mac"},
			"Linux":    {"Linux"},
			"Android":  {"Linux", "Android"},
			"ChromeOS": {"Linux", "CrOS"},
			"iOS":      {"iPhone", "iPod", "iPad"},
			"iPadOS":   {"iPad", "Mac"},
		}[in.ua.OS]
		ok := len(want) == 0
		for _, w := range want {
			ok = ok || strings.HasPrefix(p, w)
		}
		if !ok {
			add("platform", "warn", "Your platform doesn't match your User-Agent",
				"Scripts see the platform %q, while the User-Agent says %s.", p, in.ua.OS)
		}
	}

	// 5. Time zone against the IP address's country.
	if in.location.CountryCode != "" && !in.tor {
		if off, ok := geo.ZoneOffset(in.timeZone, in.now); ok {
			offs := geo.CountryOffsets(in.location.CountryCode, in.now)
			match := false
			for _, o := range offs {
				match = match || o == off
			}
			switch {
			case len(offs) == 0:
			case match:
				add("timezone", "ok", "Your time zone matches your IP location",
					"%s (%s) fits an IP address in %s.", in.timeZone, utcLabel(off), in.location.Country)
			default:
				add("timezone", "warn", "Your clock and your IP address disagree",
					"Your time zone is %s (%s), but your IP address is in %s, where clocks read %s. That's typical of a VPN or proxy, and sites use the mismatch to spot one.",
					in.timeZone, utcLabel(off), in.location.Country, offsetRange(offs))
			}
		}
	}

	// 6. Languages as scripts see them against the Accept-Language header.
	if len(in.languages) > 0 && in.acceptLanguage != "" {
		header := strings.TrimSpace(strings.Split(strings.Split(in.acceptLanguage, ",")[0], ";")[0])
		if !strings.EqualFold(header, in.languages[0]) && header != "*" {
			add("language", "warn", "Your language settings disagree",
				"Scripts see %s first, but the Accept-Language header starts with %s. Extensions that change one and not the other create a rare combination.", in.languages[0], header)
		}
	}

	// 7. Automation.
	if in.webdriver {
		add("webdriver", "warn", "This browser is under automation",
			"navigator.webdriver is set, which Selenium, Playwright and Puppeteer do. Sites treat it as a bot.")
	}
	if strings.Contains(in.uaString, "HeadlessChrome") {
		add("headless", "warn", "This is headless Chrome",
			"The User-Agent says HeadlessChrome, the mode used by scrapers and test runners.")
	}

	// 8. Network type.
	switch {
	case in.tor:
		add("tor", "ok", "You're connecting through Tor",
			"Your IP address is a Tor exit relay, so sites see that you use Tor but not where you are. Tor Browser also makes your fingerprint match other Tor users'.")
	case in.hosting:
		add("hosting", "warn", "Your IP address belongs to a hosting or VPN network",
			"%s (AS%d) runs servers rather than home connections. Many sites treat such addresses as VPN, proxy or bot traffic and show extra checks.", in.network.Org, in.network.ASN)
	}

	// 9. Anti-fingerprinting defences.
	if in.canvasNoise || in.audioNoise {
		what := "canvas"
		if in.audioNoise && !in.canvasNoise {
			what = "audio"
		} else if in.audioNoise {
			what = "canvas and audio"
		}
		add("noise", "ok", "Your browser randomizes "+what+" readings",
			"Reading the same hidden %s twice gave different results, so those readings can't be used to recognize you.", what)
	}
	if in.canvasExportNoise && !in.canvasNoise {
		add("export-noise", "info", "Your browser disguises exported canvas images",
			"Images that scripts export from a canvas come back slightly altered each session, which defeats the most common fingerprinting scripts. This page read the drawn pixels directly instead, and those were not altered.")
	}
	if in.gpc {
		add("gpc", "ok", "Global Privacy Control is on",
			"Your browser tells sites not to sell or share your data. In California, Colorado and some other places they must honor it.")
	}
	if in.adblock {
		add("adblock", "info", "An ad blocker is active",
			"Elements that look like ads were hidden. That protects you, though sites can detect it and it adds a little to your fingerprint.")
	}
	return out
}

func majorVersion(v string) int {
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func utcLabel(off int) string {
	sign := "+"
	if off < 0 {
		sign, off = "−", -off
	}
	h, m := off/3600, off%3600/60
	if m != 0 {
		return fmt.Sprintf("UTC%s%d:%02d", sign, h, m)
	}
	return fmt.Sprintf("UTC%s%d", sign, h)
}

func offsetRange(offs []int) string {
	if len(offs) == 1 {
		return utcLabel(offs[0])
	}
	return utcLabel(offs[0]) + " to " + utcLabel(offs[len(offs)-1])
}
