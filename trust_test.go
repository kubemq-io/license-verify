package licenseverify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	licenseverify "github.com/kubemq-io/license-verify"
	"github.com/kubemq-io/license-verify/internal/testsign"
)

func TestTrustBundle_AddPEMAndJWK(t *testing.T) {
	s := testsign.New(t, "k1")
	b := licenseverify.NewTrustBundle()
	require.NoError(t, b.AddPEM("k1", s.PublicPEM(t)))
	jwk := strings.Replace(string(s.PublicJWK(t)), `"kid":"k1",`, "", 1)
	require.NoError(t, b.AddJWK("k1-jwk", []byte(jwk)))
	assert.Equal(t, []string{"k1", "k1-jwk"}, b.Kids())
	assert.Equal(t, 2, b.Len())

	h1, ok := b.KeyHash("k1")
	require.True(t, ok)
	h2, ok := b.KeyHash("k1-jwk")
	require.True(t, ok)
	assert.Equal(t, h1, h2, "same key via PEM and JWK must pin to the same hash")

	der, err := x509.MarshalPKIXPublicKey(s.PublicKey())
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(der), h1)

	_, ok = b.KeyHash("missing")
	assert.False(t, ok)
}

func TestTrustBundle_Errors(t *testing.T) {
	s := testsign.New(t, "k1")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		add  func(b *licenseverify.TrustBundle) error
		want error
	}{
		{"empty kid", func(b *licenseverify.TrustBundle) error { return b.AddPEM("", s.PublicPEM(t)) }, licenseverify.ErrEmptyKid},
		{"duplicate kid", func(b *licenseverify.TrustBundle) error {
			_ = b.AddPEM("k1", s.PublicPEM(t))
			return b.AddPEM("k1", s.PublicPEM(t))
		}, licenseverify.ErrDuplicateKid},
		{"RSA key rejected", func(b *licenseverify.TrustBundle) error { return b.AddPEM("rsa", rsaPEM) }, licenseverify.ErrKeyType},
		{"P-384 rejected", func(b *licenseverify.TrustBundle) error { return b.AddKey("p384", &p384.PublicKey) }, licenseverify.ErrKeyType},
		{"nil key rejected", func(b *licenseverify.TrustBundle) error { return b.AddKey("nil", nil) }, licenseverify.ErrKeyType},
		{"garbage PEM", func(b *licenseverify.TrustBundle) error { return b.AddPEM("g", []byte("not pem")) }, licenseverify.ErrKeyEncoding},
		{"wrong PEM block type", func(b *licenseverify.TrustBundle) error {
			return b.AddPEM("c", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaDER}))
		}, licenseverify.ErrKeyEncoding},
		{"garbage JWK", func(b *licenseverify.TrustBundle) error { return b.AddJWK("j", []byte("{")) }, licenseverify.ErrKeyEncoding},
		{"JWK wrong curve", func(b *licenseverify.TrustBundle) error {
			return b.AddJWK("j", []byte(`{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`))
		}, licenseverify.ErrKeyType},
		{"JWK kid mismatch", func(b *licenseverify.TrustBundle) error { return b.AddJWK("different", s.PublicJWK(t)) }, licenseverify.ErrKeyEncoding},
		{"JWK point off curve", func(b *licenseverify.TrustBundle) error {
			x := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return b.AddJWK("j", []byte(`{"kty":"EC","crv":"P-256","x":"`+x+`","y":"`+x+`"}`))
		}, licenseverify.ErrKeyEncoding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := licenseverify.NewTrustBundle()
			assert.ErrorIs(t, tc.add(b), tc.want)
		})
	}
}

func TestTrustBundle_NilSafe(t *testing.T) {
	var b *licenseverify.TrustBundle
	assert.Nil(t, b.Kids())
	assert.Equal(t, 0, b.Len())
	_, ok := b.Key("x")
	assert.False(t, ok)
}
