package main

import (
	"testing"
	"time"

	"whoami/internal/geo"
)

func statusOf(checks []check, id string) string {
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func TestChecks(t *testing.T) {
	summer := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	firefox := parseUA("Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0")
	france := geo.Location{Country: "France", CountryCode: "FR"}

	consistent := runChecks(checkInput{
		ua: firefox, platform: "Linux x86_64", languages: []string{"fr-FR"}, acceptLanguage: "fr-FR,fr;q=0.9",
		timeZone: "Europe/Paris", tlsFamily: "firefox", h2Family: "firefox", location: france, now: summer,
	})
	for _, id := range []string{"ua-tls", "ua-h2", "timezone"} {
		if s := statusOf(consistent, id); s != "ok" {
			t.Errorf("consistent browser: %s = %q, want ok", id, s)
		}
	}
	for _, id := range []string{"platform", "language", "webdriver"} {
		if s := statusOf(consistent, id); s != "" {
			t.Errorf("consistent browser: unexpected %s check (%s)", id, s)
		}
	}

	// A Chrome handshake under a Firefox User-Agent, a Windows platform, a
	// New York clock on a French IP address, and mismatched languages.
	spoofed := runChecks(checkInput{
		ua: firefox, platform: "Win32", languages: []string{"en-US"}, acceptLanguage: "fr-FR,fr;q=0.9",
		timeZone: "America/New_York", tlsFamily: "chromium", h2Family: "chromium", location: france, now: summer,
		hints: &clientHints{Brands: []string{"Chromium 141"}},
	})
	for _, id := range []string{"ua-tls", "ua-h2", "uach", "platform", "timezone", "language"} {
		if s := statusOf(spoofed, id); s != "warn" {
			t.Errorf("spoofed browser: %s = %q, want warn", id, s)
		}
	}

	tool := runChecks(checkInput{ua: parseUA("curl/8.5.0"), tlsFamily: "openssl", now: summer})
	if s := statusOf(tool, "ua-tls"); s != "info" {
		t.Errorf("curl: ua-tls = %q, want info", s)
	}
}

func TestUTCLabel(t *testing.T) {
	for off, want := range map[int]string{0: "UTC+0", 7200: "UTC+2", -18000: "UTC−5", 19800: "UTC+5:30"} {
		if got := utcLabel(off); got != want {
			t.Errorf("utcLabel(%d) = %s, want %s", off, got, want)
		}
	}
}
