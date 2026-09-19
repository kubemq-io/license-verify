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

	_, err := licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256"}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingKid, "no kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "kid": ""}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMissingKid, "empty kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "kid": "k2"}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrUnknownKid, "unknown kid")

	_, err = licenseverify.Verify(s.SignHeader(t, map[string]any{"alg": "ES256", "kid": 7}, base), bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrMalformed, "non-string kid")
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
