package licenseverify

import "errors"

// Sentinel errors. Every failure returned by this package wraps exactly one of
// these, so callers can classify with errors.Is.
var (
	// ErrMalformed: the token is not a three-segment compact JWS or a segment
	// is not valid unpadded base64url / JSON.
	ErrMalformed = errors.New("licenseverify: malformed token")
	// ErrAlgorithm: the header `alg` is anything other than ES256.
	ErrAlgorithm = errors.New("licenseverify: unsupported algorithm (ES256 only)")
	// ErrCritHeader: the header carries a `crit` member, which is never accepted.
	ErrCritHeader = errors.New("licenseverify: crit header not supported")
	// ErrMissingKid: the header has no `kid`.
	ErrMissingKid = errors.New("licenseverify: missing kid header")
	// ErrUnknownKid: the header `kid` is not in the trust bundle.
	ErrUnknownKid = errors.New("licenseverify: unknown kid")
	// ErrSignature: the ES256 signature does not verify under the selected key.
	ErrSignature = errors.New("licenseverify: invalid signature")
	// ErrMissingExp: the payload has no `exp`.
	ErrMissingExp = errors.New("licenseverify: missing exp claim")
	// ErrExpired: `exp` (plus leeway) is in the past.
	ErrExpired = errors.New("licenseverify: token expired")
	// ErrNotYetValid: `nbf` (minus leeway) is in the future.
	ErrNotYetValid = errors.New("licenseverify: token not yet valid")
	// ErrIssuer: `iss` is not Issuer.
	ErrIssuer = errors.New("licenseverify: unexpected issuer")
	// ErrAudience: `aud` is not Audience.
	ErrAudience = errors.New("licenseverify: unexpected audience")
	// ErrNoTrustBundle: Verify was called with a nil or empty bundle.
	ErrNoTrustBundle = errors.New("licenseverify: no trust bundle")

	// ErrKeyType: the key is not an ECDSA P-256 public key.
	ErrKeyType = errors.New("licenseverify: key is not ECDSA P-256")
	// ErrDuplicateKid: the kid is already in the bundle.
	ErrDuplicateKid = errors.New("licenseverify: duplicate kid")
	// ErrEmptyKid: an empty kid was offered to the bundle.
	ErrEmptyKid = errors.New("licenseverify: empty kid")
	// ErrKeyEncoding: the PEM / JWK bytes could not be parsed.
	ErrKeyEncoding = errors.New("licenseverify: cannot parse public key")

	// ErrArmor: the armored file is not a KUBEMQ LICENSE armor (wrong or legacy
	// header, bad base64, or the body is not a compact JWS).
	ErrArmor = errors.New("licenseverify: invalid license armor")

	// ErrNotRevocation: the token is not a revocation assertion (`kmq.revoked` != true).
	ErrNotRevocation = errors.New("licenseverify: not a revocation assertion")
	// ErrJTIMismatch: the assertion's `jti` is not the expected license id.
	ErrJTIMismatch = errors.New("licenseverify: jti mismatch")
	// ErrNonceMismatch: the assertion's `kmq.nonce` does not echo the request nonce.
	ErrNonceMismatch = errors.New("licenseverify: nonce mismatch")
	// ErrMissingIat: the assertion has no `iat`.
	ErrMissingIat = errors.New("licenseverify: missing iat claim")
	// ErrStaleAssertion: the assertion's `iat` is more than 10 minutes from now.
	ErrStaleAssertion = errors.New("licenseverify: assertion iat outside the 10-minute window")
	// ErrAssertionWindow: the assertion's `exp - iat` exceeds 15 minutes.
	ErrAssertionWindow = errors.New("licenseverify: assertion validity exceeds 15 minutes")
)
