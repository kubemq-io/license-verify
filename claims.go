package licenseverify

// Issuer is the only accepted `iss` value.
const Issuer = "https://license.kubemq.io"

// Audience is the only accepted `aud` value.
const Audience = "kubemq-server"

// License modes carried in `kmq.mode`.
const (
	ModeOnline  = "online"
	ModeOffline = "offline"
)

// Claims is the verified payload of a KubeMQ license token (lease, offline
// file, or revocation assertion). The JSON keys are flat: `kmq.plan` is a
// top-level member named "kmq.plan", not a nested object.
//
// Times are unix seconds. A zero `iat`/`nbf` means the claim was absent;
// `exp` is required by Verify, so a returned Claims always has a non-zero Exp.
type Claims struct {
	JTI       string `json:"jti"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	ExpiresAt int64  `json:"exp"`

	// Plan is the commercial plan: trial / pro / enterprise / ...
	Plan string `json:"kmq.plan,omitempty"`
	// Mode is ModeOnline or ModeOffline; it drives refresh and usage reporting.
	Mode string `json:"kmq.mode,omitempty"`
	// LicenseExp is the commercial expiry (informational for the server).
	LicenseExp int64 `json:"kmq.license_exp,omitempty"`
	// MaxInstances is the installation cap (0 = unlimited).
	MaxInstances int `json:"kmq.max_instances,omitempty"`
	// Fingerprint (online) is the installation this lease was issued to.
	Fingerprint string `json:"kmq.fingerprint,omitempty"`
	// Fingerprints (offline) lists the allowed installations (empty = unbound).
	Fingerprints []string `json:"kmq.fingerprints,omitempty"`
	// GraceDays is the fail-open grace after lease expiry when the backend is unreachable.
	GraceDays int `json:"kmq.grace_days,omitempty"`
	// OverCap (online) marks an installation that exceeds MaxInstances.
	OverCap bool `json:"kmq.over_cap,omitempty"`
	// Silent (online) marks a license with no usage received for 72 h.
	Silent bool `json:"kmq.silent,omitempty"`
	// Revoked is present only in a revocation assertion.
	Revoked bool `json:"kmq.revoked,omitempty"`
	// Reason is the human-readable revocation reason.
	Reason string `json:"kmq.reason,omitempty"`
	// Nonce echoes the client's request nonce in a revocation assertion.
	Nonce string `json:"kmq.nonce,omitempty"`
	// TokenVersion is bumped by any admin mutation of the license.
	TokenVersion int `json:"kmq.token_version,omitempty"`
}
