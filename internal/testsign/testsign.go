// Package testsign signs tokens with ephemeral keys for this module's tests.
// It is internal and must never be imported by production code: it is the
// only place in the module that touches a private key.
package testsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	licenseverify "github.com/kubemq-io/license-verify"
)

var b64 = base64.RawURLEncoding

// Signer holds an ephemeral P-256 key under a kid.
type Signer struct {
	Kid string
	key *ecdsa.PrivateKey
}

// New generates an ephemeral P-256 signer.
func New(t testing.TB, kid string) *Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &Signer{Kid: kid, key: key}
}

// PublicKey returns the verifying key.
func (s *Signer) PublicKey() *ecdsa.PublicKey { return &s.key.PublicKey }

// PublicPEM returns the verifying key as a PEM "PUBLIC KEY" block.
func (s *Signer) PublicPEM(t testing.TB) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// PublicJWK returns the verifying key as a JWK document.
func (s *Signer) PublicJWK(t testing.TB) []byte {
	t.Helper()
	pub := s.key.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	out, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "kid": s.Kid,
		"x": b64.EncodeToString(x), "y": b64.EncodeToString(y),
	})
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return out
}

// Bundle returns a TrustBundle containing only this signer's key.
func (s *Signer) Bundle(t testing.TB) *licenseverify.TrustBundle {
	t.Helper()
	b := licenseverify.NewTrustBundle()
	if err := b.AddPEM(s.Kid, s.PublicPEM(t)); err != nil {
		t.Fatalf("add pem: %v", err)
	}
	return b
}

// Sign produces an ES256 compact JWS with {"alg":"ES256","kid":<kid>,"typ":"JWT"}.
func (s *Signer) Sign(t testing.TB, claims any) string {
	t.Helper()
	return s.SignHeader(t, map[string]any{"alg": "ES256", "kid": s.Kid, "typ": "JWT"}, claims)
}

// SignHeader produces an ES256 compact JWS with an arbitrary header (the
// header is signed as given; the signature is always a real ES256 signature).
func (s *Signer) SignHeader(t testing.TB, hdr map[string]any, claims any) string {
	t.Helper()
	input := signingInput(t, hdr, claims)
	sum := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return input + "." + b64.EncodeToString(sig)
}

// SignNone produces an unsigned token with alg=none and an empty signature segment.
func SignNone(t testing.TB, kid string, claims any) string {
	t.Helper()
	return signingInput(t, map[string]any{"alg": "none", "kid": kid, "typ": "JWT"}, claims) + "."
}

// SignRS512 produces a token signed with a fresh RSA-2048 key under alg=RS512.
func SignRS512(t testing.TB, kid string, claims any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	input := signingInput(t, map[string]any{"alg": "RS512", "kid": kid, "typ": "JWT"}, claims)
	sum := sha512.Sum512([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, sum[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return input + "." + b64.EncodeToString(sig)
}

// SignHS256 produces an HMAC-signed token under alg=HS256 keyed with secret.
func SignHS256(t testing.TB, kid string, claims any, secret []byte) string {
	t.Helper()
	input := signingInput(t, map[string]any{"alg": "HS256", "kid": kid, "typ": "JWT"}, claims)
	mac := hmacSHA256(secret, []byte(input))
	return input + "." + b64.EncodeToString(mac)
}

// BaseClaims returns a valid online lease issued at now, expiring in 7 days.
func BaseClaims(now time.Time) licenseverify.Claims {
	return licenseverify.Claims{
		JTI:          "3b6d1a2e-7f4c-4d3a-9c1e-1f2a3b4c5d6e",
		Issuer:       licenseverify.Issuer,
		Audience:     licenseverify.Audience,
		Subject:      "Acme Corp",
		IssuedAt:     now.Unix(),
		NotBefore:    now.Unix(),
		ExpiresAt:    now.Add(7 * 24 * time.Hour).Unix(),
		Plan:         "pro",
		Mode:         licenseverify.ModeOnline,
		LicenseExp:   now.Add(365 * 24 * time.Hour).Unix(),
		MaxInstances: 3,
		Fingerprint:  "fp-1",
		GraceDays:    7,
		TokenVersion: 1,
	}
}

// OfflineClaims returns a valid offline file issued at now, bound to two
// installations, expiring in 365 days.
func OfflineClaims(now time.Time) licenseverify.Claims {
	return licenseverify.Claims{
		JTI:          "a2b4c6d8-1e3f-4a5b-8c7d-9e0f1a2b3c4d",
		Issuer:       licenseverify.Issuer,
		Audience:     licenseverify.Audience,
		Subject:      "Globex Industries",
		IssuedAt:     now.Unix(),
		NotBefore:    now.Unix(),
		ExpiresAt:    now.Add(365 * 24 * time.Hour).Unix(),
		Plan:         "enterprise",
		Mode:         licenseverify.ModeOffline,
		LicenseExp:   now.Add(365 * 24 * time.Hour).Unix(),
		MaxInstances: 10,
		Fingerprints: []string{"fp-1", "fp-2"},
		TokenVersion: 1,
	}
}

// RevocationClaims returns a valid revocation assertion for jti/nonce at now.
func RevocationClaims(now time.Time, jti, nonce string) licenseverify.Claims {
	return licenseverify.Claims{
		JTI:       jti,
		Issuer:    licenseverify.Issuer,
		Audience:  licenseverify.Audience,
		Subject:   "Acme Corp",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
		Revoked:   true,
		Reason:    "non-payment",
		Nonce:     nonce,
	}
}

// ClaimsMap round-trips Claims through JSON into a map so tests can add or
// delete individual members (e.g. delete "exp").
func ClaimsMap(t testing.TB, c licenseverify.Claims) map[string]any {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return m
}

func signingInput(t testing.TB, hdr map[string]any, claims any) string {
	t.Helper()
	h, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p)
}
