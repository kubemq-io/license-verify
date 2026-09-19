package licenseverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
)

// TrustBundle maps key ids to ECDSA P-256 public keys. It is safe to share
// once populated; populate it at startup and do not mutate it concurrently.
type TrustBundle struct {
	keys map[string]*ecdsa.PublicKey
}

// NewTrustBundle returns an empty bundle.
func NewTrustBundle() *TrustBundle {
	return &TrustBundle{keys: make(map[string]*ecdsa.PublicKey)}
}

// AddKey registers a P-256 public key under kid.
func (b *TrustBundle) AddKey(kid string, pub *ecdsa.PublicKey) error {
	if kid == "" {
		return ErrEmptyKid
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w (kid %q)", ErrKeyType, kid)
	}
	if b.keys == nil {
		b.keys = make(map[string]*ecdsa.PublicKey)
	}
	if _, dup := b.keys[kid]; dup {
		return fmt.Errorf("%w %q", ErrDuplicateKid, kid)
	}
	b.keys[kid] = pub
	return nil
}

// AddPEM registers the PEM-encoded SubjectPublicKeyInfo ("PUBLIC KEY" block)
// under kid.
func (b *TrustBundle) AddPEM(kid string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("%w: no PEM block (kid %q)", ErrKeyEncoding, kid)
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("%w: PEM block type %q, want PUBLIC KEY (kid %q)", ErrKeyEncoding, block.Type, kid)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v (kid %q)", ErrKeyEncoding, err, kid)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %T (kid %q)", ErrKeyType, pub, kid)
	}
	return b.AddKey(kid, ec)
}

// AddJWK registers a JSON Web Key ({"kty":"EC","crv":"P-256","x":..,"y":..})
// under kid. A `kid` member inside the JWK, if present, must equal kid.
func (b *TrustBundle) AddJWK(kid string, jwkJSON []byte) error {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return fmt.Errorf("%w: %v (kid %q)", ErrKeyEncoding, err, kid)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return fmt.Errorf("%w: kty=%q crv=%q (kid %q)", ErrKeyType, jwk.Kty, jwk.Crv, kid)
	}
	if jwk.Kid != "" && jwk.Kid != kid {
		return fmt.Errorf("%w: JWK kid %q does not match %q", ErrKeyEncoding, jwk.Kid, kid)
	}
	x, err := base64.RawURLEncoding.Strict().DecodeString(jwk.X)
	if err != nil {
		return fmt.Errorf("%w: x: %v (kid %q)", ErrKeyEncoding, err, kid)
	}
	y, err := base64.RawURLEncoding.Strict().DecodeString(jwk.Y)
	if err != nil {
		return fmt.Errorf("%w: y: %v (kid %q)", ErrKeyEncoding, err, kid)
	}
	if len(x) != 32 || len(y) != 32 {
		return fmt.Errorf("%w: coordinate length (kid %q)", ErrKeyEncoding, kid)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return fmt.Errorf("%w: point not on curve (kid %q)", ErrKeyEncoding, kid)
	}
	return b.AddKey(kid, pub)
}

// Kids returns the registered key ids in sorted order.
func (b *TrustBundle) Kids() []string {
	if b == nil {
		return nil
	}
	kids := make([]string, 0, len(b.keys))
	for k := range b.keys {
		kids = append(kids, k)
	}
	sort.Strings(kids)
	return kids
}

// Len returns the number of registered keys.
func (b *TrustBundle) Len() int {
	if b == nil {
		return 0
	}
	return len(b.keys)
}

// Key returns the public key registered under kid.
func (b *TrustBundle) Key(kid string) (*ecdsa.PublicKey, bool) {
	if b == nil {
		return nil, false
	}
	pub, ok := b.keys[kid]
	return pub, ok
}

// KeyHash returns SHA-256 over the DER SubjectPublicKeyInfo of the key
// registered under kid, so consumers can pin the exact key they embed.
func (b *TrustBundle) KeyHash(kid string) (hash [32]byte, ok bool) {
	pub, found := b.Key(kid)
	if !found {
		return hash, false
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return hash, false
	}
	return sha256.Sum256(der), true
}
