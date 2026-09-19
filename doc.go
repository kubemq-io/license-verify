// Package licenseverify verifies KubeMQ license leases, offline license files,
// and revocation assertions.
//
// It implements the frozen v1 token contract: compact JWS, ES256 only, a
// required `kid` header that must match a key in the caller's TrustBundle, a
// required `exp`, a fixed issuer (Issuer) and audience (Audience), and a
// five-minute leeway on `nbf`/`exp`.
//
// The package holds public keys only. It never handles a private key and
// makes no network calls. Signing exists solely in an internal test helper.
package licenseverify
