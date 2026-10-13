package main

import "testing"

func TestParseUA(t *testing.T) {
	cases := []struct {
		ua                        string
		browser, version, os, osv string
		mobile, tool              bool
		family                    string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
			"Chrome", "141.0.0.0", "Windows", "10/11", false, false, "chromium"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
			"Edge", "141.0.0.0", "Windows", "10/11", false, false, "chromium"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:155.0) Gecko/20100101 Firefox/155.0",
			"Firefox", "155.0", "macOS", "10.15", false, false, "firefox"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
			"Safari", "26.0", "macOS", "10.15.7", false, false, "apple"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.7390.41 Mobile/15E148 Safari/604.1",
			"Chrome", "141.0.7390.41", "iOS", "18.6", true, false, "apple"},
		{"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
			"Chrome", "141.0.0.0", "Android", "10", true, false, "chromium"},
		{"curl/8.5.0", "curl", "8.5.0", "", "", false, true, "tool"},
		{"python-requests/2.32.3", "Python", "2.32.3", "", "", false, true, "tool"},
	}
	for _, c := range cases {
		u := parseUA(c.ua)
		if u.Browser != c.browser || u.Version != c.version || u.OS != c.os || u.OSVersion != c.osv || u.Mobile != c.mobile || u.Tool != c.tool {
			t.Errorf("%s\n got %+v", c.ua, u)
		}
		if f := u.family(); f != c.family {
			t.Errorf("%s: family %s, want %s", c.ua, f, c.family)
		}
	}
}

func TestRefineWithClientHints(t *testing.T) {
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

	brave := parseUA(chrome)
	brave.refine(&clientHints{Brands: []string{"Brave 141", "Not?A_Brand 8", "Chromium 141"}, Platform: "Windows", PlatformVersion: "19.0.0"})
	if brave.Browser != "Brave" || brave.OSVersion != "11" {
		t.Errorf("brave: %+v", brave)
	}

	win10 := parseUA(chrome)
	win10.refine(&clientHints{
		Brands:          []string{"Google Chrome 141", "Chromium 141"},
		FullVersionList: []string{"Google Chrome 141.0.7390.55", "Chromium 141.0.7390.55"},
		Platform:        "Windows", PlatformVersion: "10.0.0",
	})
	if win10.Browser != "Chrome" || win10.Version != "141.0.7390.55" || win10.OSVersion != "10" {
		t.Errorf("chrome on windows 10: %+v", win10)
	}
	if got := win10.label(); got != "Chrome 141 on Windows 10" {
		t.Errorf("label = %q", got)
	}

	mac := parseUA("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
	mac.refine(&clientHints{Brands: []string{"Google Chrome 141"}, Platform: "macOS", PlatformVersion: "26.0.0"})
	if mac.OS != "macOS" || mac.OSVersion != "26.0" {
		t.Errorf("chrome on macOS: %+v", mac)
	}
}
