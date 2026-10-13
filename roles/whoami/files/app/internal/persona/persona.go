// Package persona turns an opaque 128-bit identifier into something a person
// can recognise at a glance: a name, an animal, two colours, a guilloché
// rosette and an 8-character code. Two different identifiers almost always
// look different; the same identifier always looks the same.
package persona

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Persona is the visual identity derived from an ID.
type Persona struct {
	Name      string  `json:"name"`
	Adjective string  `json:"adjective"`
	ColorName string  `json:"colorName"`
	Animal    string  `json:"animal"`
	Emoji     string  `json:"emoji"`
	Code      string  `json:"code"`
	Color     string  `json:"color"`
	Color2    string  `json:"color2"`
	Rosette   Rosette `json:"rosette"`
}

// Rosette parameterises the guilloché pattern drawn by the page: two braided
// rings and a centre star, like the security printing on a passport page.
type Rosette struct {
	OuterLobes   int     `json:"outerLobes"`
	OuterDepth   float64 `json:"outerDepth"`
	OuterStrands int     `json:"outerStrands"`
	InnerLobes   int     `json:"innerLobes"`
	InnerDepth   float64 `json:"innerDepth"`
	InnerStrands int     `json:"innerStrands"`
	StarPoints   int     `json:"starPoints"`
	StarLoop     float64 `json:"starLoop"`
	Twist        float64 `json:"twist"`
}

// bits reads an identifier as a big-endian bit stream.
type bits struct {
	b   [16]byte
	pos int
}

func (r *bits) take(n int) int {
	v := 0
	for range n {
		byteIdx, bitIdx := r.pos/8%16, 7-r.pos%8
		v = v<<1 | int(r.b[byteIdx]>>bitIdx&1)
		r.pos++
	}
	return v
}

// crockford is Douglas Crockford's base32 alphabet: no I, L, O or U, so codes
// survive being read aloud or copied by hand. It is also a subset of the
// characters allowed in a passport's machine-readable zone.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Code returns n base32 characters taken from the start of id.
func Code(id [16]byte, n int) string {
	r := bits{b: id}
	var sb strings.Builder
	for range n {
		sb.WriteByte(crockford[r.take(5)])
	}
	return sb.String()
}

// From derives the persona for id.
func From(id [16]byte) Persona {
	code := Code(id, 8)
	r := bits{b: id, pos: 45} // the first 45 bits are the code (9 characters in the MRZ)
	adj := adjectives[r.take(7)]
	ci := r.take(6)
	animal := animals[r.take(6)]
	c2 := r.take(6)
	if c2 == ci {
		c2 = (c2 + 23) % len(colors)
	}
	p := Persona{
		Adjective: adj,
		ColorName: colors[ci].name,
		Animal:    animal.name,
		Emoji:     animal.emoji,
		Code:      code[:4] + "-" + code[4:],
		Color:     colors[ci].hex,
		Color2:    colors[c2].hex,
		Rosette: Rosette{
			OuterLobes:   9 + r.take(4),                  // 9..24
			OuterDepth:   0.04 + float64(r.take(3))*0.01, // 0.04..0.11
			OuterStrands: 4 + r.take(3),                  // 4..11
			InnerLobes:   4 + r.take(3),                  // 4..11
			InnerDepth:   0.08 + float64(r.take(3))*0.02, // 0.08..0.22
			InnerStrands: 3 + r.take(3),                  // 3..10
			StarPoints:   3 + r.take(3),                  // 3..10
			StarLoop:     0.35 + float64(r.take(3))*0.08, // 0.35..0.91
			Twist:        float64(r.take(4)) / 16,        // 0..0.94 of a lobe
		},
	}
	r2 := func(f float64) float64 { return math.Round(f*100) / 100 }
	p.Rosette.OuterDepth, p.Rosette.InnerDepth = r2(p.Rosette.OuterDepth), r2(p.Rosette.InnerDepth)
	p.Rosette.StarLoop, p.Rosette.Twist = r2(p.Rosette.StarLoop), r2(p.Rosette.Twist)
	p.Name = adj + " " + p.ColorName + " " + p.Animal
	return p
}

// MRZ renders two 44-character lines in the layout of a passport's
// machine-readable zone (ICAO 9303, TD3). The document number is the identity
// code, the birth date is when the fingerprint was first seen, the expiry is
// when it will be deleted, and the optional data field carries the device
// code. Check digits are computed exactly as on a real passport.
func MRZ(p Persona, id [16]byte, device [16]byte, born, expires time.Time) [2]string {
	name := mrzField(strings.ToUpper(p.Animal)+"<<"+strings.ToUpper(p.Adjective+"<"+p.ColorName), 39)
	line1 := "P<WWW" + name

	doc := Code(id, 9)
	dob := born.UTC().Format("060102")
	exp := expires.UTC().Format("060102")
	opt := Code(device, 14)
	parts := []string{
		doc + checkDigit(doc),
		dob + checkDigit(dob),
		exp + checkDigit(exp),
		opt + checkDigit(opt),
	}
	composite := parts[0] + parts[1] + parts[2] + parts[3]
	line2 := parts[0] + "XXX" + parts[1] + "<" + parts[2] + parts[3] + checkDigit(composite)
	return [2]string{line1, line2}
}

func mrzField(s string, n int) string {
	var sb strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '<':
			sb.WriteRune(c)
		case c == ' ' || c == '-':
			sb.WriteByte('<')
		}
	}
	out := sb.String()
	if len(out) > n {
		return out[:n]
	}
	return out + strings.Repeat("<", n-len(out))
}

// checkDigit is the ICAO 9303 check digit: weights 7, 3, 1 repeating;
// digits count as themselves, letters A-Z as 10-35, filler '<' as 0.
func checkDigit(s string) string {
	weights := [3]int{7, 3, 1}
	sum := 0
	for i, c := range s {
		v := 0
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		}
		sum += v * weights[i%3]
	}
	return fmt.Sprint(sum % 10)
}
