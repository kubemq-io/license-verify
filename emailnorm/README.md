# emailnorm

Canonical e-mail normalization shared by the Go back office and the
JavaScript website. Both implementations must pass every vector in
`vectors.json`; the file is the specification.

## Rules (in order)

1. Trim leading/trailing whitespace. Empty → `empty`.
2. Unicode NFKC.
3. Lowercase.
4. Split on `@`: none → `missing_at`; more than one → `multiple_at`;
   empty local part → `empty_local`; empty domain → `empty_domain`.
5. Local part must be printable ASCII: any code point above U+007F →
   `non_ascii_local`; control characters or spaces → `invalid_local`.
6. Strip `+tag`: everything from the first `+` to the `@` is removed. An empty
   result → `empty_local`. Dots are **kept**.
7. Domain → IDNA (UTS #46 lookup profile, STD3 rules, DNS length limits) →
   punycode ASCII. Empty labels, leading/trailing dots, invalid characters →
   `invalid_domain`.
8. Every domain label, in its Unicode form, must be single-script (Common and
   Inherited ignored; Han+Hiragana+Katakana, Han+Hangul and Han+Bopomofo are
   allowed together). Otherwise → `mixed_script`. This also catches homographs
   that arrive already punycoded.
9. Result: `local@domain`. `email_hash = sha256(result)`.

`RegistrableDomain` is the public-suffix-list eTLD+1 of the domain
(`a.b.co.uk` → `b.co.uk`); a domain that is itself a public suffix or has no
dots is returned unchanged.

## vectors.json schema

An array of objects:

| Field | Type | Meaning |
|---|---|---|
| `input` | string | raw input, exactly as a user might type it (may contain whitespace, fullwidth or non-ASCII characters) |
| `normalized` | string \| null | expected output; `null` when the input must be rejected |
| `error` | string \| null | expected reason code; `null` on success. Exactly one of `normalized` / `error` is non-null |
| `registrable_domain` | string \| null | expected `RegistrableDomain(normalized)`; `null` on error vectors |
| `note` | string (optional) | human-readable explanation, ignored by tests |

Reason codes: `empty`, `missing_at`, `multiple_at`, `empty_local`,
`empty_domain`, `non_ascii_local`, `invalid_local`, `invalid_domain`,
`mixed_script`.

A conforming implementation must also be idempotent: normalizing a
`normalized` value returns it unchanged.
