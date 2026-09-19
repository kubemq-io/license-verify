# license-verify

Verify-only library for KubeMQ Next license tokens: leases, offline license
files, and revocation assertions. It ships **public keys only** and makes no
network calls. It is the single verifier every KubeMQ client (server,
operator) imports.

Module: `github.com/kubemq-io/license-verify` · Go 1.25+ · dependencies:
standard library for the verifier; `golang.org/x/net`, `golang.org/x/text`
for `emailnorm`.

## Frozen contract v1 (2026-09-19)

The token contract below is frozen as of **2026-09-19**. Any change to the
claim set, the algorithm, the issuer/audience values, the armor header, or the
revocation windows is a v2 and requires a coordinated release of every client.

### Verifier rules

- Compact JWS, **ES256 only**. The header `alg` is checked before any claim is
  parsed; `none`, `RS*`, `HS*`, `PS*`, `ES384/512` fail with `ErrAlgorithm`.
- Header `kid` is **required** and must name a key in the caller's
  `TrustBundle` (`ErrMissingKid`, `ErrUnknownKid`). A `crit` header is rejected.
- `exp` is **required** (`ErrMissingExp`).
- `iss` must equal `https://license.kubemq.io` (`Issuer`); `aud` must equal
  `kubemq-server` (`Audience`).
- 5-minute leeway on `nbf` and `exp`.
- No labels map, no label-based expiry, no legacy `kid`, no file-level
  deactivation marker.

### Claims

| Claim | Type | Meaning |
|---|---|---|
| `jti` | uuid | license id |
| `iss`, `aud` | string | fixed values above |
| `sub` | string | issued-to (customer display name) |
| `iat`, `nbf`, `exp` | unix | **lease** validity. Online: `exp = iat + 7d`. Offline: `exp` ≤ issuance + 1 year. |
| `kmq.plan` | string | `trial` / `pro` / `enterprise` / … |
| `kmq.mode` | `online` \| `offline` | drives refresh + usage (offline: neither) |
| `kmq.license_exp` | unix | **commercial** expiry; informational for the server (shown in `GET /license`, dashboard, warnings); the backend stops issuing leases after it |
| `kmq.max_instances` | int | installation cap (0 = unlimited) |
| `kmq.fingerprint` | string | **online:** the installation this lease was issued to; server refuses a lease whose value ≠ its own fingerprint |
| `kmq.fingerprints` | []string | **offline:** allowed installations (empty = unbound) |
| `kmq.grace_days` | int | fail-open grace after lease `exp` when the backend is unreachable (online; default 7, admin 0–30; trials 0) |
| `kmq.over_cap` | bool | online: this installation exceeds `max_instances`; server logs loudly every minute |
| `kmq.silent` | bool | online: no usage received for 72 h; server logs a warning every minute; lease length capped at 24 h while set |
| `kmq.revoked` | bool | present only in a **revocation assertion** |
| `kmq.token_version` | int | bumped by any admin mutation; lets the server detect a changed entitlement at refresh |

The `kmq.*` keys are flat top-level JSON members (`"kmq.plan": "pro"`), not a
nested `kmq` object.

### Revocation assertion

A JWS with the same `kid`, the license `jti`, `kmq.revoked = true`,
`kmq.reason`, `iat`, `kmq.nonce` (echo of the client's request nonce) and
`exp = iat + 15 min`. `VerifyRevocation` additionally requires the `jti` and
nonce to match, `iat` within 10 minutes of now, and `exp − iat ≤ 15 minutes`,
so a captured assertion cannot be replayed.

### Offline file armor

```
-----BEGIN KUBEMQ LICENSE-----
<standard base64 of the compact JWS, 64 columns>
-----END KUBEMQ LICENSE-----
```

`Dearmor` accepts this armor or a bare compact JWS and rejects every other
header, including the legacy `KUBEMQ KEY` / `KUBEMQ LICENSE KEY` formats.

## Usage

```go
import licenseverify "github.com/kubemq-io/license-verify"

//go:embed keys/kubemq-2026-09.pem
var key202609 []byte

bundle := licenseverify.NewTrustBundle()
if err := bundle.AddPEM("kubemq-2026-09", key202609); err != nil {
    log.Fatal(err)
}

// Pin the embedded key: a swapped key fails the build's tests.
hash, _ := bundle.KeyHash("kubemq-2026-09")
if hex.EncodeToString(hash[:]) != "…expected sha256 of the DER SubjectPublicKeyInfo…" {
    log.Fatal("trust bundle key mismatch")
}

// Lease or offline file (either armored or bare).
jws, err := licenseverify.Dearmor(fileBytes)
if err != nil { /* not a KUBEMQ LICENSE file */ }

claims, err := licenseverify.Verify(jws, bundle, licenseverify.VerifyOptions{})
if err != nil { /* errors.Is(err, licenseverify.ErrExpired) etc. */ }
fmt.Println(claims.Plan, claims.Mode, claims.MaxInstances)

// Revocation assertion received at refresh.
_, err = licenseverify.VerifyRevocation(assertion, bundle, licenseverify.VerifyOptions{}, claims.JTI, requestNonce)
```

`VerifyOptions.Now` injects a clock for tests; `Leeway` overrides the 5-minute
default.

## Security notes

- **ES256 only.** The algorithm is taken from the header and compared before
  any signature or claim work; there is no algorithm negotiation.
- **`kid` required.** Every token must name the key that signed it; keys are
  looked up in the caller's bundle only, never from the token.
- **Pin the key hash.** `TrustBundle.KeyHash(kid)` is SHA-256 over the DER
  SubjectPublicKeyInfo. Consumers assert it in a test so a swapped or
  corrupted embedded key fails the build.
- **Public keys only.** A guard test fails if any non-test source in this
  module contains a PEM private-key marker. Signing for tests lives in
  `internal/testsign`, which is not importable from outside the module.
- **Strict decoding.** Unpadded base64url with strict trailing-bit checks;
  JSON with trailing data rejected; signature must be exactly 64 bytes.
- Key rotation: publish the new public key here, ship it in client releases,
  then start signing with the new `kid`. Clients advertise their trusted kids
  to the backend, which refuses to sign with a kid a client does not list.

## emailnorm

`emailnorm` normalizes e-mail addresses for trial dedupe (NFKC → lowercase →
ASCII local part → strip `+tag` → punycode domain → single-script labels) and
ships the shared `vectors.json` that the JavaScript implementation must also
pass. See `emailnorm/README.md`.

## Development

```
go vet ./...
go test -race ./...
```

## License

Apache-2.0 — see `LICENSE`.
