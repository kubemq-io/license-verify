package licenseverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// DefaultLeeway is the clock tolerance applied to `nbf` and `exp`.
const DefaultLeeway = 5 * time.Minute

// Revocation assertion windows (see the contract, §2.5).
const (
	// RevocationIatWindow bounds |now - iat| for a revocation assertion.
	RevocationIatWindow = 10 * time.Minute
	// RevocationMaxLifetime bounds exp - iat for a revocation assertion.
	RevocationMaxLifetime = 15 * time.Minute
)

// VerifyOptions tunes Verify. The zero value is valid: wall-clock time and
// DefaultLeeway.
type VerifyOptions struct {
	// Now supplies the verification time; nil means time.Now.
	Now func() time.Time
	// Leeway is the tolerance on nbf/exp; zero means DefaultLeeway. A negative
	// value is treated as zero leeway.
	Leeway time.Duration
}

func (o VerifyOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o VerifyOptions) leeway() time.Duration {
	switch {
	case o.Leeway == 0:
		return DefaultLeeway
	case o.Leeway < 0:
		return 0
	default:
		return o.Leeway
	}
}

var b64 = base64.RawURLEncoding.Strict()

type header struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

// Verify checks a compact JWS and returns its claims.
//
// Order of checks: token shape → header `alg` (ES256 only, decided before any
// claim is parsed) → no `crit` → `kid` present and in bundle → ES256 signature
// → claims parse → `exp` present → `iss` → `aud` → `nbf`/`exp` against
// opts.Now with leeway.
func Verify(token string, bundle *TrustBundle, opts VerifyOptions) (*Claims, error) {
	if bundle == nil || bundle.Len() == 0 {
		return nil, ErrNoTrustBundle
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformed, len(parts))
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	var hdr header
	if err := strictUnmarshal(rawHeader, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("%w: alg=%q", ErrAlgorithm, hdr.Alg)
	}
	if len(hdr.Crit) != 0 && !bytes.Equal(hdr.Crit, []byte("null")) {
		return nil, ErrCritHeader
	}
	if hdr.Kid == "" {
		return nil, ErrMissingKid
	}
	pub, ok := bundle.Key(hdr.Kid)
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownKid, hdr.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	if !verifyES256(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrSignature
	}

	rawPayload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	var present map[string]json.RawMessage
	if err := strictUnmarshal(rawPayload, &present); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	if _, has := present["exp"]; !has {
		return nil, ErrMissingExp
	}
	var claims Claims
	if err := strictUnmarshal(rawPayload, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	if claims.Issuer != Issuer {
		return nil, fmt.Errorf("%w: %q", ErrIssuer, claims.Issuer)
	}
	if claims.Audience != Audience {
		return nil, fmt.Errorf("%w: %q", ErrAudience, claims.Audience)
	}

	now := opts.now()
	leeway := opts.leeway()
	exp := time.Unix(claims.ExpiresAt, 0)
	if !now.Before(exp.Add(leeway)) {
		return nil, fmt.Errorf("%w: exp=%s now=%s", ErrExpired, exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if claims.NotBefore != 0 {
		nbf := time.Unix(claims.NotBefore, 0)
		if now.Add(leeway).Before(nbf) {
			return nil, fmt.Errorf("%w: nbf=%s now=%s", ErrNotYetValid, nbf.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
	}
	return &claims, nil
}

// VerifyRevocation verifies a revocation assertion: a token that passes
// Verify and additionally has `kmq.revoked == true`, `jti == expectedJTI`,
// `kmq.nonce == expectedNonce`, an `iat` within RevocationIatWindow of now,
// and `exp - iat <= RevocationMaxLifetime`.
//
// expectedJTI and expectedNonce must be non-empty; an assertion can never be
// matched against an absent nonce.
func VerifyRevocation(token string, bundle *TrustBundle, opts VerifyOptions, expectedJTI, expectedNonce string) (*Claims, error) {
	claims, err := Verify(token, bundle, opts)
	if err != nil {
		return nil, err
	}
	if !claims.Revoked {
		return nil, ErrNotRevocation
	}
	if expectedJTI == "" || claims.JTI != expectedJTI {
		return nil, ErrJTIMismatch
	}
	if expectedNonce == "" || claims.Nonce != expectedNonce {
		return nil, ErrNonceMismatch
	}
	if claims.IssuedAt == 0 {
		return nil, ErrMissingIat
	}
	now := opts.now()
	iat := time.Unix(claims.IssuedAt, 0)
	if d := now.Sub(iat); d > RevocationIatWindow || d < -RevocationIatWindow {
		return nil, fmt.Errorf("%w: iat=%s now=%s", ErrStaleAssertion, iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if claims.ExpiresAt < claims.IssuedAt || time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > RevocationMaxLifetime {
		return nil, fmt.Errorf("%w: exp-iat=%ds", ErrAssertionWindow, claims.ExpiresAt-claims.IssuedAt)
	}
	return claims, nil
}

// verifyES256 checks a raw r||s (64-byte) P-256 signature over SHA-256(input).
func verifyES256(pub *ecdsa.PublicKey, input, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256(input)
	return ecdsa.Verify(pub, sum[:], r, s)
}

// strictUnmarshal decodes exactly one JSON value and rejects trailing data.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}
