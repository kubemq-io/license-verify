// Package licenseverify verifies KubeMQ license leases, offline license files,
// and revocation assertions.
//
// It implements the frozen v1 token contract: compact JWS, ES256 only, a
// closed header of exactly {alg, kid, typ:"JWT"}, a required `kid` that must
// match a key in the caller's TrustBundle, required `exp` and `iat`, a fixed
// issuer (Issuer) and audience (Audience), and a five-minute leeway on
// `nbf`/`exp`/`iat`. Verify is the generic entry; VerifyLease, VerifyOffline
// and VerifyRevocation add the per-kind claim rules.
//
// The package holds public keys only. It never handles a private key and
// makes no network calls. Signing exists solely in an internal test helper.
package licenseverify
