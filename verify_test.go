package licenseverify_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	licenseverify "github.com/kubemq-io/license-verify"
	"github.com/kubemq-io/license-verify/internal/testsign"
)

var fixedNow = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func optsAt(t time.Time) licenseverify.VerifyOptions {
	return licenseverify.VerifyOptions{Now: func() time.Time { return t }}
}

func TestVerify_ValidLease(t *testing.T) {
	s := testsign.New(t, "k1")
	want := testsign.BaseClaims(fixedNow)
	want.Fingerprints = []string{"a", "b"}
	tok := s.Sign(t, want)

	got, err := licenseverify.Verify(tok, s.Bundle(t), optsAt(fixedNow))
	require.NoError(t, err)
	assert.Equal(t, &want, got)
}

func TestVerify_ClaimKeysAreFlat(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(fixedNow))
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"kmq.plan":"pro"`)
	assert.Contains(t, string(payload), `"kmq.max_instances":3`)
	assert.NotContains(t, string(payload), `"kmq":{`)
}

func TestVerify_Table(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	base := testsign.BaseClaims(fixedNow)

	tests := []struct {
		name   string
		token  func(t *testing.T) string
		opts   licenseverify.VerifyOptions
		bundle *licenseverify.TrustBundle
		want   error
	}{
		{
			name:  "wrong issuer",
			token: func(t *testing.T) string { c := base; c.Issuer = "https://evil.example"; return s.Sign(t, c) },
			want:  licenseverify.ErrIssuer,
		},
		{
			name:  "wrong audience",
			token: func(t *testing.T) string { c := base; c.Audience = "kubemq-operator"; return s.Sign(t, c) },
			want:  licenseverify.ErrAudience,
		},
		{
			name: "audience as array is malformed",
			token: func(t *testing.T) string {
				m := testsign.ClaimsMap(t, base)
				m["aud"] = []string{licenseverify.Audience}
				return s.Sign(t, m)
			},
			want: licenseverify.ErrMalformed,
		},
		{
			name: "missing exp",
			token: func(t *testing.T) string {
				m := testsign.ClaimsMap(t, base)
				delete(m, "exp")
				return s.Sign(t, m)
			},
			want: licenseverify.ErrMissingExp,
		},
		{
			name:  "expired beyond leeway",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			opts:  optsAt(time.Unix(base.ExpiresAt, 0).Add(5*time.Minute + time.Second)),
			want:  licenseverify.ErrExpired,
		},
		{
			name:  "expired exactly at leeway edge",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			opts:  optsAt(time.Unix(base.ExpiresAt, 0).Add(5 * time.Minute)),
			want:  licenseverify.ErrExpired,
		},
		{
			name:  "expired within leeway passes",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			opts:  optsAt(time.Unix(base.ExpiresAt, 0).Add(4 * time.Minute)),
			want:  nil,
		},
		{
			name: "nbf in the future beyond leeway",
			token: func(t *testing.T) string {
				c := base
				c.NotBefore = fixedNow.Add(10 * time.Minute).Unix()
				return s.Sign(t, c)
			},
			want: licenseverify.ErrNotYetValid,
		},
		{
			name: "nbf in the future within leeway passes",
			token: func(t *testing.T) string {
				c := base
				c.NotBefore = fixedNow.Add(4 * time.Minute).Unix()
				return s.Sign(t, c)
			},
			want: nil,
		},
		{
			name:  "custom leeway is honored",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			opts:  licenseverify.VerifyOptions{Now: func() time.Time { return time.Unix(base.ExpiresAt, 0).Add(4 * time.Minute) }, Leeway: time.Minute},
			want:  licenseverify.ErrExpired,
		},
		{
			name:  "negative leeway means zero",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			opts:  licenseverify.VerifyOptions{Now: func() time.Time { return time.Unix(base.ExpiresAt, 0) }, Leeway: -1},
			want:  licenseverify.ErrExpired,
		},
		{
			name:   "nil bundle",
			token:  func(t *testing.T) string { return s.Sign(t, base) },
			bundle: nil,
			want:   licenseverify.ErrNoTrustBundle,
		},
		{
			name:   "empty bundle",
			token:  func(t *testing.T) string { return s.Sign(t, base) },
			bundle: licenseverify.NewTrustBundle(),
			want:   licenseverify.ErrNoTrustBundle,
		},
		{
			name:  "two segments",
			token: func(t *testing.T) string { tok := s.Sign(t, base); return tok[:strings.LastIndex(tok, ".")] },
			want:  licenseverify.ErrMalformed,
		},
		{
			name:  "empty token",
			token: func(t *testing.T) string { return "" },
			want:  licenseverify.ErrMalformed,
		},
		{
			name:  "padded base64 rejected",
			token: func(t *testing.T) string { return s.Sign(t, base) + "==" },
			want:  licenseverify.ErrMalformed,
		},
		{
			name: "tampered payload fails signature",
			token: func(t *testing.T) string {
				tok := s.Sign(t, base)
				parts := strings.Split(tok, ".")
				c := base
				c.MaxInstances = 1000
				forged := s.Sign(t, c)
				parts[1] = strings.Split(forged, ".")[1]
				return strings.Join(parts, ".")
			},
			want: licenseverify.ErrSignature,
		},
		{
			name: "signed by a different key under the same kid",
			token: func(t *testing.T) string {
				other := testsign.New(t, "k1")
				return other.Sign(t, base)
			},
			want: licenseverify.ErrSignature,
		},
		{
			name: "signature of the wrong length",
			token: func(t *testing.T) string {
				parts := strings.Split(s.Sign(t, base), ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 63))
				return strings.Join(parts, ".")
			},
			want: licenseverify.ErrSignature,
		},
		{
			name: "crit header rejected",
			token: func(t *testing.T) string {
				return s.SignHeader(t, map[string]any{"alg": "ES256", "kid": "k1", "typ": "JWT", "crit": []string{"exp"}}, base)
			},
			want: licenseverify.ErrCritHeader,
		},
		{
			name:  "valid token from a second bundle key",
			token: func(t *testing.T) string { return s.Sign(t, base) },
			bundle: func() *licenseverify.TrustBundle {
				b := licenseverify.NewTrustBundle()
				require.NoError(t, b.AddPEM("other", testsign.New(t, "other").PublicPEM(t)))
				require.NoError(t, b.AddPEM("k1", s.PublicPEM(t)))
				return b
			}(),
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle
			if tc.bundle != nil || tc.name == "nil bundle" {
				b = tc.bundle
			}
			opts := tc.opts
			if opts.Now == nil {
				opts = optsAt(fixedNow)
			}
			claims, err := licenseverify.Verify(tc.token(t), b, opts)
			if tc.want == nil {
				require.NoError(t, err)
				require.NotNil(t, claims)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, claims)
		})
	}
}

func TestVerify_DefaultsToWallClock(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(time.Now()))
	_, err := licenseverify.Verify(tok, s.Bundle(t), licenseverify.VerifyOptions{})
	require.NoError(t, err)
}

func TestVerifyRevocation(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"
	const nonce = "n-123"

	tests := []struct {
		name  string
		token func(t *testing.T) string
		jti   string
		nonce string
		now   time.Time
		want  error
	}{
		{
			name:  "valid assertion",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, nonce)) },
			jti:   jti, nonce: nonce, now: fixedNow,
		},
		{
			name:  "valid assertion received 9 minutes later",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, nonce)) },
			jti:   jti, nonce: nonce, now: fixedNow.Add(9 * time.Minute),
		},
		{
			name:  "not a revocation (plain lease)",
			token: func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); return s.Sign(t, c) },
			jti:   jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrNotRevocation,
		},
		{
			name:  "jti mismatch",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, "other-id", nonce)) },
			jti:   jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrJTIMismatch,
		},
		{
			name:  "nonce mismatch (replay under a new request nonce)",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, nonce)) },
			jti:   jti, nonce: "n-456", now: fixedNow,
			want: licenseverify.ErrNonceMismatch,
		},
		{
			name:  "empty expected nonce never matches",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "")) },
			jti:   jti, nonce: "", now: fixedNow,
			want: licenseverify.ErrNonceMismatch,
		},
		{
			name:  "iat older than 10 minutes (captured assertion replayed later)",
			token: func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, nonce)) },
			jti:   jti, nonce: nonce, now: fixedNow.Add(10*time.Minute + time.Second),
			want: licenseverify.ErrStaleAssertion,
		},
		{
			name: "iat more than the 5-minute leeway in the future (rejected by Verify)",
			token: func(t *testing.T) string {
				return s.Sign(t, testsign.RevocationClaims(fixedNow.Add(6*time.Minute), jti, nonce))
			},
			jti: jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrIssuedInFuture,
		},
		{
			name: "iat 4 minutes in the future is within leeway",
			token: func(t *testing.T) string {
				return s.Sign(t, testsign.RevocationClaims(fixedNow.Add(4*time.Minute), jti, nonce))
			},
			jti: jti, nonce: nonce, now: fixedNow,
		},
		{
			name: "missing iat",
			token: func(t *testing.T) string {
				m := testsign.ClaimsMap(t, testsign.RevocationClaims(fixedNow, jti, nonce))
				delete(m, "iat")
				return s.Sign(t, m)
			},
			jti: jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrMissingIat,
		},
		{
			name: "exp - iat exceeds 15 minutes",
			token: func(t *testing.T) string {
				c := testsign.RevocationClaims(fixedNow, jti, nonce)
				c.ExpiresAt = fixedNow.Add(16 * time.Minute).Unix()
				return s.Sign(t, c)
			},
			jti: jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrAssertionWindow,
		},
		{
			name: "expired assertion fails before the revocation checks",
			token: func(t *testing.T) string {
				return s.Sign(t, testsign.RevocationClaims(fixedNow.Add(-30*time.Minute), jti, nonce))
			},
			jti: jti, nonce: nonce, now: fixedNow,
			want: licenseverify.ErrExpired,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := licenseverify.VerifyRevocation(tc.token(t), bundle, optsAt(tc.now), tc.jti, tc.nonce)
			if tc.want == nil {
				require.NoError(t, err)
				assert.True(t, claims.Revoked)
				assert.Equal(t, tc.nonce, claims.Nonce)
				return
			}
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, claims)
		})
	}
}

func TestVerifyLease(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"

	tests := []struct {
		name  string
		token func(t *testing.T) string
		want  error
	}{
		{"valid lease", func(t *testing.T) string { return s.Sign(t, testsign.BaseClaims(fixedNow)) }, nil},
		{"offline file", func(t *testing.T) string { return s.Sign(t, testsign.OfflineClaims(fixedNow)) }, licenseverify.ErrNotLease},
		{"revocation assertion", func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "n")) }, licenseverify.ErrNotLease},
		{"lease with kmq.revoked", func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); c.Revoked = true; return s.Sign(t, c) }, licenseverify.ErrNotLease},
		{"missing mode", func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); c.Mode = ""; return s.Sign(t, c) }, licenseverify.ErrNotLease},
		{"unknown mode", func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); c.Mode = "hybrid"; return s.Sign(t, c) }, licenseverify.ErrNotLease},
		{"uppercase mode", func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); c.Mode = "Online"; return s.Sign(t, c) }, licenseverify.ErrNotLease},
		{"empty fingerprint", func(t *testing.T) string { c := testsign.BaseClaims(fixedNow); c.Fingerprint = ""; return s.Sign(t, c) }, licenseverify.ErrNotLease},
		{"fingerprints present", func(t *testing.T) string {
			c := testsign.BaseClaims(fixedNow)
			c.Fingerprints = []string{"fp-1"}
			return s.Sign(t, c)
		}, licenseverify.ErrNotLease},
		{"fingerprints present as empty array passes", func(t *testing.T) string {
			m := testsign.ClaimsMap(t, testsign.BaseClaims(fixedNow))
			m["kmq.fingerprints"] = []string{}
			return s.Sign(t, m)
		}, nil},
		{"missing nbf", func(t *testing.T) string {
			m := testsign.ClaimsMap(t, testsign.BaseClaims(fixedNow))
			delete(m, "nbf")
			return s.Sign(t, m)
		}, licenseverify.ErrMissingNbf},
		{"expired lease fails in Verify first", func(t *testing.T) string {
			return s.Sign(t, testsign.BaseClaims(fixedNow.Add(-8*24*time.Hour)))
		}, licenseverify.ErrExpired},
		{"bad signature fails in Verify first", func(t *testing.T) string {
			return testsign.New(t, "k1").Sign(t, testsign.BaseClaims(fixedNow))
		}, licenseverify.ErrSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := licenseverify.VerifyLease(tc.token(t), bundle, optsAt(fixedNow))
			if tc.want == nil {
				require.NoError(t, err)
				assert.Equal(t, licenseverify.ModeOnline, claims.Mode)
				assert.NotEmpty(t, claims.Fingerprint)
				return
			}
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, claims)
		})
	}
}

func TestVerifyOffline(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"

	tests := []struct {
		name  string
		token func(t *testing.T) string
		want  error
	}{
		{"valid bound file", func(t *testing.T) string { return s.Sign(t, testsign.OfflineClaims(fixedNow)) }, nil},
		{"valid unbound file (no fingerprints)", func(t *testing.T) string {
			c := testsign.OfflineClaims(fixedNow)
			c.Fingerprints = nil
			return s.Sign(t, c)
		}, nil},
		{"valid unbound file (empty fingerprints array)", func(t *testing.T) string {
			m := testsign.ClaimsMap(t, testsign.OfflineClaims(fixedNow))
			m["kmq.fingerprints"] = []string{}
			return s.Sign(t, m)
		}, nil},
		{"armored file after Dearmor", func(t *testing.T) string {
			jws, err := licenseverify.Dearmor(licenseverify.Armor(s.Sign(t, testsign.OfflineClaims(fixedNow))))
			require.NoError(t, err)
			return jws
		}, nil},
		{"online lease", func(t *testing.T) string { return s.Sign(t, testsign.BaseClaims(fixedNow)) }, licenseverify.ErrNotOffline},
		{"revocation assertion", func(t *testing.T) string { return s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "n")) }, licenseverify.ErrNotOffline},
		{"file with kmq.revoked", func(t *testing.T) string {
			c := testsign.OfflineClaims(fixedNow)
			c.Revoked = true
			return s.Sign(t, c)
		}, licenseverify.ErrNotOffline},
		{"missing mode", func(t *testing.T) string { c := testsign.OfflineClaims(fixedNow); c.Mode = ""; return s.Sign(t, c) }, licenseverify.ErrNotOffline},
		{"fingerprint present", func(t *testing.T) string {
			c := testsign.OfflineClaims(fixedNow)
			c.Fingerprint = "fp-1"
			return s.Sign(t, c)
		}, licenseverify.ErrNotOffline},
		{"missing nbf", func(t *testing.T) string {
			m := testsign.ClaimsMap(t, testsign.OfflineClaims(fixedNow))
			delete(m, "nbf")
			return s.Sign(t, m)
		}, licenseverify.ErrMissingNbf},
		{"expired file fails in Verify first", func(t *testing.T) string {
			return s.Sign(t, testsign.OfflineClaims(fixedNow.Add(-2*365*24*time.Hour)))
		}, licenseverify.ErrExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := licenseverify.VerifyOffline(tc.token(t), bundle, optsAt(fixedNow))
			if tc.want == nil {
				require.NoError(t, err)
				assert.Equal(t, licenseverify.ModeOffline, claims.Mode)
				assert.Empty(t, claims.Fingerprint)
				return
			}
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, claims)
		})
	}
}

// TestVerifyKinds_CrossRejection: each kind verifier rejects the other two
// kinds, and the generic Verify accepts all three.
func TestVerifyKinds_CrossRejection(t *testing.T) {
	s := testsign.New(t, "k1")
	bundle := s.Bundle(t)
	const jti = "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e"
	lease := s.Sign(t, testsign.BaseClaims(fixedNow))
	offline := s.Sign(t, testsign.OfflineClaims(fixedNow))
	assertion := s.Sign(t, testsign.RevocationClaims(fixedNow, jti, "n"))

	for name, tok := range map[string]string{"lease": lease, "offline": offline, "assertion": assertion} {
		_, err := licenseverify.Verify(tok, bundle, optsAt(fixedNow))
		require.NoError(t, err, "generic Verify accepts a %s", name)
	}

	_, err := licenseverify.VerifyLease(offline, bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrNotLease)
	_, err = licenseverify.VerifyLease(assertion, bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrNotLease)

	_, err = licenseverify.VerifyOffline(lease, bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrNotOffline)
	_, err = licenseverify.VerifyOffline(assertion, bundle, optsAt(fixedNow))
	assert.ErrorIs(t, err, licenseverify.ErrNotOffline)

	_, err = licenseverify.VerifyRevocation(lease, bundle, optsAt(fixedNow), jti, "n")
	assert.ErrorIs(t, err, licenseverify.ErrNotRevocation)
	_, err = licenseverify.VerifyRevocation(offline, bundle, optsAt(fixedNow), jti, "n")
	assert.ErrorIs(t, err, licenseverify.ErrNotRevocation)
}
