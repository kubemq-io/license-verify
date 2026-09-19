package licenseverify_test

// Guard tests: the invariants the token contract (§2.2 / §7.1a) calls out by
// name. Each one must keep failing loudly if the verifier ever loosens.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	licenseverify "github.com/kubemq-io/license-verify"
	"github.com/kubemq-io/license-verify/internal/testsign"
)

func TestGuard_AlgorithmIsES256Only(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)

	tests := []struct {
		name  string
		token string
	}{
		{"RS512", testsign.SignRS512(t, "k1", base)},
		{"none", testsign.SignNone(t, "k1", base)},
		{"HS256 keyed with the public key bytes", testsign.SignHS256(t, "k1", base, s.PublicPEM(t))},
		{"ES384 label on an ES256 signature", s.SignHeader(t, map[string]any{"alg": "ES384", "kid": "k1"}, base)},
		{"PS256 label", s.SignHeader(t, map[string]any{"alg": "PS256", "kid": "k1"}, base)},
		{"lowercase es256", s.SignHeader(t, map[string]any{"alg": "es256", "kid": "k1"}, base)},
		{"missing alg", s.SignHeader(t, map[string]any{"kid": "k1"}, base)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := licenseverify.Verify(tc.token, bundle, optsAt(fixedNow))
			assert.ErrorIs(t, err, licenseverify.ErrAlgorithm)
		})
	}
}

func TestGuard_KidRequiredAndKnown(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)

	_, err := licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "typ": "JWT"}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingKid, "no kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": ""}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingKid, "empty kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "k2"}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrUnknownKid, "unknown kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": 7}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMalformed, "non-string kid")
}

// TestGuard_HeaderIsClosed pins contract §1.1: the protected header is exactly
// {alg, kid, typ}. Any other member — including the key-injection members
// jwk / jku / x5u / x5c — is rejected before the payload is touched.
func TestGuard_HeaderIsClosed(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)
	good := map[string]any{"alg": "ES256", "kid": "k1", "typ": "JWT"}

	_, err := licenseverify.Verify(s.SignHeader(t, good, base), bundle, optsAt(fixedNow))
	require.NoError(t, err, "the canonical header verifies")

	extra := map[string]any{
		"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
		"jku": "https://evil.example/keys",
		"x5u": "https://evil.example/cert.pem",
		"x5c": []string{"MIIB"},
		"cty": "JWT",
		"exp": 1,
		"zip": "DEF",
		"enc": "A256GCM",
	}
	for name, value := range extra {
		t.Run("member "+name, func(t *testing.T) {
			hdr := map[string]any{}
			for k, v := range good {
				hdr[k] = v
			}
			hdr[name] = value
			_, err := licenseverify.Verify(s.SignHeader(t, hdr, base), bundle, optsAt(fixedNow))
			assert.ErrorIs(t, err, licenseverify.ErrHeader)
		})
	}

	typs := map[string]any{"missing": nil, "empty": "", "lowercase jwt": "jwt", "JOSE": "JOSE", "at+jwt": "at+jwt", "non-string": 1}
	for name, value := range typs {
		t.Run("typ "+name, func(t *testing.T) {
			hdr := map[string]any{"alg": "ES256", "kid": "k1"}
			if value != nil {
				hdr["typ"] = value
			}
			_, err := licenseverify.Verify(s.SignHeader(t, hdr, base), bundle, optsAt(fixedNow))
			if name == "non-string" {
				assert.ErrorIs(t, err, licenseverify.ErrMalformed)
				return
			}
			assert.ErrorIs(t, err, licenseverify.ErrHeader)
		})
	}

	t.Run("crit keeps its own sentinel", func(t *testing.T) {
		_, err := licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "kid": "k1", "typ": "JWT", "crit": []string{"exp"}}, base), bundle, optsAt(fixedNow))
		assert.ErrorIs(t, err, licenseverify.ErrCritHeader)
	})
	t.Run("alg is decided before typ", func(t *testing.T) {
		_, err := licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "none", "kid": "k1"}, base), bundle, optsAt(fixedNow))
		assert.ErrorIs(t, err, licenseverify.ErrAlgorithm)
	})
	t.Run("unknown member is decided before alg", func(t *testing.T) {
		_, err := licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "none", "kid": "k1", "typ": "JWT", "jwk": "x"}, base), bundle, optsAt(fixedNow))
		assert.ErrorIs(t, err, licenseverify.ErrHeader)
	})
}

// TestGuard_IatRules pins contract §1.2: `iat` is required on every token and
// may not be more than the leeway (300 s) in the future.
func TestGuard_IatRules(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)

	m := testsign.ClaimsMap(t, base)
	delete(m, "iat")
	_, err := licenseverify.Verify(s.Sign(t, m), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingIat, "missing iat")

	c := base
	c.IssuedAt = fixedNow.Add(5*time.Minute + time.Second).Unix()
	_, err = licenseverify.Verify(s.Sign(t, c), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrIssuedInFuture, "iat 301 s in the future")

	c.IssuedAt = fixedNow.Add(5 * time.Minute).Unix()
	_, err = licenseverify.Verify(s.Sign(t, c), bundle, optsAt(fixedNow))
	require.NoError(t, err, "iat exactly 300 s in the future is within leeway")

	c.IssuedAt = fixedNow.Add(4 * time.Minute).Unix()
	_, err = licenseverify.Verify(s.Sign(t, c), bundle, optsAt(fixedNow))
	require.NoError(t, err, "iat 240 s in the future")

	c.IssuedAt = fixedNow.Add(2 * time.Minute).Unix()
	_, err = licenseverify.Verify(s.Sign(t, c), bundle, licenseverify.VerifyOptions{Now: func() time.Time { return fixedNow }, Leeway: time.Minute})
	assert.ErrorIs(t, err, licenseverify.ErrIssuedInFuture, "custom leeway applies to iat")

	c.IssuedAt = fixedNow.Add(-365 * 24 * time.Hour).Unix()
	_, err = licenseverify.Verify(s.Sign(t, c), bundle, optsAt(fixedNow))
	require.NoError(t, err, "an old iat is fine for Verify")
}

// TestGuard_NbfRequiredForLeaseAndOffline pins contract §1.3: `nbf` is
// required on leases and offline files (not on assertions).
func TestGuard_NbfRequiredForLeaseAndOffline(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)

	m := testsign.ClaimsMap(t, testsign.BaseClaims(fixedNow))
	delete(m, "nbf")
	tok := s.Sign(t, m)
	_, err := licenseverify.Verify(tok, bundle, optsAt(fixedNow))
	require.NoError(t, err, "generic Verify does not require nbf")
	_, err = licenseverify.VerifyLease(tok, bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingNbf)

	m = testsign.ClaimsMap(t, testsign.OfflineClaims(fixedNow))
	delete(m, "nbf")
	_, err = licenseverify.VerifyOffline(s.Sign(t, m), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingNbf)

	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"
	_, err = licenseverify.VerifyRevocation(s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "n")), bundle, optsAt(fixedNow), jti, "n")
	require.NoError(t, err, "assertions carry no nbf and still verify")
}

// TestGuard_RevocationLifetimeOverflow: exp-iat of 18446744074 s (2^64/1e9,
// rounded up) used to wrap to ~0.3 s when converted to a time.Duration and
// slip under the 15-minute cap. The comparison now runs in int64 seconds.
func TestGuard_RevocationLifetimeOverflow(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"

	for _, lifetime := range []int64{18446744074, 18446744073, 9223372037, 1 << 62, 901} {
		c := testsign.RevocationClaims(fixedNow, jti, "n")
		c.ExpiresAt = c.IssuedAt + lifetime
		_, err := licenseverify.VerifyRevocation(s.Sign(t, c), bundle, optsAt(fixedNow), jti, "n")
		assert.ErrorIs(t, err, licenseverify.ErrAssertionWindow, "lifetime %d", lifetime)
	}
	c := testsign.RevocationClaims(fixedNow, jti, "n")
	c.ExpiresAt = c.IssuedAt + 900
	_, err := licenseverify.VerifyRevocation(s.Sign(t, c), bundle, optsAt(fixedNow), jti, "n")
	require.NoError(t, err, "exactly 900 s is the contract lifetime")

	// exp < iat cannot pass Verify (exp is in the past) but must never be
	// reachable as a negative lifetime either: exp just inside leeway, iat
	// after it.
	c = testsign.RevocationClaims(fixedNow, jti, "n")
	c.ExpiresAt = fixedNow.Add(-time.Minute).Unix()
	c.IssuedAt = fixedNow.Unix()
	_, err = licenseverify.VerifyRevocation(s.Sign(t, c), bundle, optsAt(fixedNow), jti, "n")
	assert.ErrorIs(t, err, licenseverify.ErrAssertionWindow, "exp before iat")
}

func TestGuard_ExpIssAudRequired(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)

	m := testsign.ClaimsMap(t, base)
	delete(m, "exp")
	_, err := licenseverify.Verify(s.Sign(t, m), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingExp)

	m = testsign.ClaimsMap(t, base)
	delete(m, "iss")
	_, err = licenseverify.Verify(s.Sign(t, m), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrIssuer)

	m = testsign.ClaimsMap(t, base)
	delete(m, "aud")
	_, err = licenseverify.Verify(s.Sign(t, m), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrAudience)
}

func TestGuard_LegacyArmorHeaderFails(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(fixedNow))
	body := strings.TrimSuffix(strings.TrimPrefix(string(licenseverify.Armor(tok)), licenseverify.ArmorBegin+"\n"), licenseverify.ArmorEnd+"\n")

	legacy := []string{
		"-----BEGIN KUBEMQ LICENSE KEY-----",
		"-----BEGIN KUBEMQ KEY-----",
		"-----BEGIN KUBEMQ KEY-----                              ",
		"-----BEGIN LICENSE-----",
		"----BEGIN KUBEMQ LICENSE-----",
		"-----begin kubemq license-----",
	}
	for _, hdr := range legacy {
		t.Run(hdr, func(t *testing.T) {
			_, err := licenseverify.Dearmor([]byte(hdr + "\n" + body + licenseverify.ArmorEnd + "\n"))
			assert.ErrorIs(t, err, licenseverify.ErrArmor)
		})
	}
	// The deactivation marker of the legacy format is just garbage now.
	_, err := licenseverify.Dearmor([]byte("---deactivated---"))
	assert.ErrorIs(t, err, licenseverify.ErrArmor)
}

// TestGuard_NoPrivateKeyMarkerInSources scans every non-test Go file outside
// internal/testsign for a PEM private-key marker. The verifier must ship
// public keys only.
func TestGuard_NoPrivateKeyMarkerInSources(t *testing.T) {
	root, err := filepath.Abs(".")
	require.NoError(t, err)
	marker := "PRIVATE" + " KEY" // split so this test file itself would not trip a naive grep
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if d.Name() == ".git" || rel == filepath.Join("internal", "testsign") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), marker) {
			offenders = append(offenders, rel)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, offenders, "non-test sources must never contain a private-key marker")
}

func TestGuard_RevocationReplay(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"

	captured := s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "nonce-1"))

	_, err := licenseverify.VerifyRevocation(captured, bundle, optsAt(fixedNow), jti, "nonce-1")
	require.NoError(t, err, "first confirmation with its own nonce")

	_, err = licenseverify.VerifyRevocation(captured, bundle, optsAt(fixedNow.Add(time.Minute)), jti, "nonce-2")
	assert.ErrorIs(t, err, licenseverify.ErrNonceMismatch, "same assertion replayed under the next request nonce")

	_, err = licenseverify.VerifyRevocation(captured, bundle, optsAt(fixedNow.Add(11*time.Minute)), jti, "nonce-1")
	assert.ErrorIs(t, err, licenseverify.ErrStaleAssertion, "same assertion replayed after the 10-minute window")
}

func TestGuard_TamperedPayload(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(fixedNow))
	parts := strings.Split(tok, ".")
	forged := s.Sign(t, func() licenseverify.Claims { c := testsign.BaseClaims(fixedNow); c.Plan = "enterprise"; return c }())
	parts[1] = strings.Split(forged, ".")[1]
	_, err := licenseverify.Verify(strings.Join(parts, "."), s.Bundle(t), optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrSignature)
}

func TestGuard_ExpiryLeeway(t *testing.T) {
	s := testsign.New(t, "k1")
	base := testsign.BaseClaims(fixedNow)
	tok := s.Sign(t, base)
	exp := time.Unix(base.ExpiresAt, 0)

	_, err := licenseverify.Verify(tok, s.Bundle(t), optsAt(exp.Add(4*time.Minute+59*time.Second)))
	require.NoError(t, err, "within the 5-minute leeway")

	_, err = licenseverify.Verify(tok, s.Bundle(t), optsAt(exp.Add(5*time.Minute+time.Second)))
	assert.ErrorIs(t, err, licenseverify.ErrExpired, "beyond the 5-minute leeway")
}
