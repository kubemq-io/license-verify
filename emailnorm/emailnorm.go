// Package emailnorm normalizes e-mail addresses for identity and dedupe
// purposes, exactly as the shared vectors.json specifies, so that the Go and
// JavaScript implementations agree byte for byte.
//
// Pipeline: trim → Unicode NFKC → lowercase → split on the single "@" →
// reject a non-ASCII local part → strip "+tag" from the local part → IDNA
// (punycode) the domain → reject mixed-script domain labels → local@domain.
//
// Dots in the local part are kept: provider-specific rules (e.g. Gmail dot
// folding) are deliberately out of scope.
package emailnorm

import (
	"crypto/sha256"
	"errors"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/unicode/norm"
)

// Reason codes. Each sentinel error maps to one stable code (see Reason) that
// vectors.json uses in its "error" field.
var (
	ErrEmpty         = errors.New("emailnorm: empty address")
	ErrMissingAt     = errors.New("emailnorm: missing @")
	ErrMultipleAt    = errors.New("emailnorm: more than one @")
	ErrEmptyLocal    = errors.New("emailnorm: empty local part")
	ErrEmptyDomain   = errors.New("emailnorm: empty domain")
	ErrNonASCIILocal = errors.New("emailnorm: non-ASCII local part")
	ErrInvalidLocal  = errors.New("emailnorm: invalid character in local part")
	ErrInvalidDomain = errors.New("emailnorm: invalid domain")
	ErrMixedScript   = errors.New("emailnorm: mixed-script domain label")
)

var reasons = []struct {
	err  error
	code string
}{
	{ErrEmpty, "empty"},
	{ErrMissingAt, "missing_at"},
	{ErrMultipleAt, "multiple_at"},
	{ErrEmptyLocal, "empty_local"},
	{ErrEmptyDomain, "empty_domain"},
	{ErrNonASCIILocal, "non_ascii_local"},
	{ErrInvalidLocal, "invalid_local"},
	{ErrInvalidDomain, "invalid_domain"},
	{ErrMixedScript, "mixed_script"},
}

// Reason returns the stable code for an error produced by Normalize, or ""
// for nil / foreign errors.
func Reason(err error) string {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.code
		}
	}
	return ""
}

// Normalize returns the canonical form of email or a sentinel error.
func Normalize(email string) (string, error) {
	s := strings.TrimSpace(email)
	if s == "" {
		return "", ErrEmpty
	}
	s = norm.NFKC.String(s)
	s = strings.ToLower(s)

	at := strings.Index(s, "@")
	if at < 0 {
		return "", ErrMissingAt
	}
	if strings.Count(s, "@") > 1 {
		return "", ErrMultipleAt
	}
	local, domain := s[:at], s[at+1:]
	if local == "" {
		return "", ErrEmptyLocal
	}
	if domain == "" {
		return "", ErrEmptyDomain
	}

	for _, r := range local {
		if r > unicode.MaxASCII {
			return "", ErrNonASCIILocal
		}
		if r <= ' ' || r == 0x7f {
			return "", ErrInvalidLocal
		}
	}
	if plus := strings.Index(local, "+"); plus >= 0 {
		local = local[:plus]
		if local == "" {
			return "", ErrEmptyLocal
		}
	}

	ascii, err := normalizeDomain(domain)
	if err != nil {
		return "", err
	}
	return local + "@" + ascii, nil
}

// lookup is the IDNA profile for user-supplied domains: UTS #46 mapping with
// label validation, DNS length limits, and the STD3 ASCII rules.
var lookup = idna.New(
	idna.MapForLookup(),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
	idna.StrictDomainName(true),
	idna.BidiRule(),
)

func normalizeDomain(domain string) (string, error) {
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return "", ErrInvalidDomain
		}
	}
	ascii, err := lookup.ToASCII(domain)
	if err != nil {
		return "", errors.Join(ErrInvalidDomain, err)
	}
	// Mixed-script detection runs on the Unicode form, which also covers
	// input that arrived already punycoded.
	uni, err := lookup.ToUnicode(ascii)
	if err != nil {
		return "", errors.Join(ErrInvalidDomain, err)
	}
	for _, label := range strings.Split(uni, ".") {
		if mixedScript(label) {
			return "", ErrMixedScript
		}
	}
	return ascii, nil
}

// scriptTables is the ordered list of Unicode scripts consulted per rune.
// Common and Inherited are ignored (digits, hyphen, combining marks).
var scriptTables = func() []struct {
	name  string
	table *unicode.RangeTable
} {
	out := make([]struct {
		name  string
		table *unicode.RangeTable
	}, 0, len(unicode.Scripts))
	for name, table := range unicode.Scripts {
		if name == "Common" || name == "Inherited" {
			continue
		}
		out = append(out, struct {
			name  string
			table *unicode.RangeTable
		}{name, table})
	}
	return out
}()

// allowedMixes are the script combinations a single label may legitimately
// contain (Unicode TS #39 "highly restrictive" level).
var allowedMixes = [][]string{
	{"Han", "Hiragana", "Katakana"},
	{"Han", "Hangul"},
	{"Han", "Bopomofo"},
}

func mixedScript(label string) bool {
	seen := map[string]struct{}{}
	for _, r := range label {
		for _, s := range scriptTables {
			if unicode.Is(s.table, r) {
				seen[s.name] = struct{}{}
				break
			}
		}
	}
	if len(seen) <= 1 {
		return false
	}
	for _, mix := range allowedMixes {
		if subsetOf(seen, mix) {
			return false
		}
	}
	return true
}

func subsetOf(seen map[string]struct{}, allowed []string) bool {
	for name := range seen {
		found := false
		for _, a := range allowed {
			if a == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Hash returns SHA-256 over the normalized address (the `email_hash`).
func Hash(normalized string) [32]byte {
	return sha256.Sum256([]byte(normalized))
}

// RegistrableDomain returns the effective top-level domain plus one label of
// the normalized address's domain (a.b.co.uk → b.co.uk), using the public
// suffix list. When the domain has no registrable parent (e.g. it is itself
// a public suffix, or has no dots) the domain is returned unchanged. The
// empty string is returned when normalized has no "@".
func RegistrableDomain(normalized string) string {
	at := strings.LastIndex(normalized, "@")
	if at < 0 {
		return ""
	}
	domain := normalized[at+1:]
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return etld1
}
