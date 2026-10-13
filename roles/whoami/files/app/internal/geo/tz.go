package geo

import (
	"slices"
	"strings"
	"time"
)

// ZoneOffset returns the UTC offset in seconds of the IANA zone name at t.
// Legacy aliases browsers still report (Asia/Calcutta, Europe/Kiev) resolve
// through the tz database's backward links.
func ZoneOffset(name string, t time.Time) (int, bool) {
	if name == "" || strings.ContainsAny(name, " .") {
		return 0, false
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return 0, false
	}
	_, off := t.In(loc).Zone()
	return off, true
}

// CountryOffsets returns the distinct UTC offsets in seconds in use in a
// country at t, or nil if the country is unknown.
func CountryOffsets(countryCode string, t time.Time) []int {
	var offs []int
	for _, z := range countryZones[strings.ToUpper(countryCode)] {
		if off, ok := ZoneOffset(z, t); ok && !slices.Contains(offs, off) {
			offs = append(offs, off)
		}
	}
	slices.Sort(offs)
	return offs
}
