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

// HeaderTyp is the only accepted JOSE `typ` header value.
const HeaderTyp = "JWT"

// header is the complete set of JOSE header members a token may carry
// (contract §1.1). `crit` is listed only so it can be reported with its own
// sentinel; every other member (jwk, jku, x5u, x5c, …) is unknown and rejected.
type header struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
}

// Verify checks a compact JWS and returns its claims. It is the generic
// entry point; VerifyLease, VerifyOffline and VerifyRevocation add the
// per-kind claim rules on top of it.
//
// Order of checks: token shape → header decode (unknown members rejected) →
// header `alg` (ES256 only, decided before any claim is parsed) → no `crit`
// → `typ` == "JWT" → `kid` present and in bundle → ES256 signature → claims
// parse → `exp` and `iat` present → `iss` → `aud` → `exp`/`nbf`/`iat`
// against opts.Now with leeway (`iat` may not be more than leeway in the
// future). `nbf` is optional here; the kind verifiers require it.
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
	hdr, err := decodeHeader(rawHeader)
	if err != nil {
		return nil, err
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("%w: alg=%q", ErrAlgorithm, hdr.Alg)
	}
	if len(hdr.Crit) != 0 && !bytes.Equal(hdr.Crit, []byte("null")) {
		return nil, ErrCritHeader
	}
	if hdr.Typ != HeaderTyp {
		return nil, fmt.Errorf("%w: typ=%q", ErrHeader, hdr.Typ)
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
	if _, has := present["iat"]; !has {
		return nil, ErrMissingIat
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
	iat := time.Unix(claims.IssuedAt, 0)
	if now.Add(leeway).Before(iat) {
		return nil, fmt.Errorf("%w: iat=%s now=%s", ErrIssuedInFuture, iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return &claims, nil
}

// headerMembers are the JOSE header members Verify understands. Anything
// else is rejected before the payload is touched.
var headerMembers = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "crit": {}}

// decodeHeader parses the protected header strictly: one JSON object, no
// trailing data, no member outside headerMembers, members of the right type.
func decodeHeader(raw []byte) (header, error) {
	var members map[string]json.RawMessage
	if err := strictUnmarshal(raw, &members); err != nil {
		return header{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	for name := range members {
		if _, ok := headerMembers[name]; !ok {
			return header{}, fmt.Errorf("%w: unexpected member %q", ErrHeader, name)
		}
	}
	var hdr header
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hdr); err != nil {
		return header{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	return hdr, nil
}

// VerifyLease verifies an online lease: a token that passes Verify and has
// `kmq.mode == "online"`, a non-empty `kmq.fingerprint`, no
// `kmq.fingerprints`, no `kmq.revoked`, and an `nbf`. A revocation assertion
// or an offline file fails with ErrNotLease.
func VerifyLease(token string, bundle *TrustBundle, opts VerifyOptions) (*Claims, error) {
	claims, err := Verify(token, bundle, opts)
	if err != nil {
		return nil, err
	}
	switch {
	case claims.Revoked:
		return nil, fmt.Errorf("%w: kmq.revoked is set", ErrNotLease)
	case claims.Mode != ModeOnline:
		return nil, fmt.Errorf("%w: kmq.mode=%q", ErrNotLease, claims.Mode)
	case claims.Fingerprint == "":
		return nil, fmt.Errorf("%w: kmq.fingerprint is empty", ErrNotLease)
	case len(claims.Fingerprints) != 0:
		return nil, fmt.Errorf("%w: kmq.fingerprints is present", ErrNotLease)
	case claims.NotBefore == 0:
		return nil, ErrMissingNbf
	}
	return claims, nil
}

// VerifyOffline verifies an offline license file: a token that passes Verify
// and has `kmq.mode == "offline"`, an empty `kmq.fingerprint`, no
// `kmq.revoked`, and an `nbf`. `kmq.fingerprints` may be empty (unbound). A
// revocation assertion or an online lease fails with ErrNotOffline.
func VerifyOffline(token string, bundle *TrustBundle, opts VerifyOptions) (*Claims, error) {
	claims, err := Verify(token, bundle, opts)
	if err != nil {
		return nil, err
	}
	switch {
	case claims.Revoked:
		return nil, fmt.Errorf("%w: kmq.revoked is set", ErrNotOffline)
	case claims.Mode != ModeOffline:
		return nil, fmt.Errorf("%w: kmq.mode=%q", ErrNotOffline, claims.Mode)
	case claims.Fingerprint != "":
		return nil, fmt.Errorf("%w: kmq.fingerprint is present", ErrNotOffline)
	case claims.NotBefore == 0:
		return nil, ErrMissingNbf
	}
	return claims, nil
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
	// Contract §1.5: an assertion carries no entitlement claims. A token that
	// mixes lease/file claims with kmq.revoked is malformed, never a confirmation.
	if claims.Mode != "" || claims.Plan != "" || claims.LicenseExp != 0 || claims.MaxInstances != 0 ||
		claims.GraceDays != 0 || claims.TokenVersion != 0 || claims.Fingerprint != "" ||
		len(claims.Fingerprints) != 0 || claims.OverCap || claims.Silent {
		return nil, ErrAssertionClaims
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
	// Compare in seconds as int64: converting exp-iat to a time.Duration
	// would overflow (and wrap to a small value) for exp-iat > ~292 years.
	lifetime := claims.ExpiresAt - claims.IssuedAt
	if claims.ExpiresAt < claims.IssuedAt || lifetime < 0 || lifetime > int64(RevocationMaxLifetime/time.Second) {
		return nil, fmt.Errorf("%w: exp-iat=%ds", ErrAssertionWindow, lifetime)
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
