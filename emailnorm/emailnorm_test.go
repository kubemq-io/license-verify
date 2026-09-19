package emailnorm_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kubemq-io/license-verify/emailnorm"
)

func TestHash(t *testing.T) {
	assert.Equal(t, sha256.Sum256([]byte("alice@example.com")), emailnorm.Hash("alice@example.com"))
}

func TestReason(t *testing.T) {
	assert.Equal(t, "", emailnorm.Reason(nil))
	assert.Equal(t, "", emailnorm.Reason(assert.AnError))
	assert.Equal(t, "mixed_script", emailnorm.Reason(emailnorm.ErrMixedScript))
}

func TestRegistrableDomain_NoAt(t *testing.T) {
	assert.Equal(t, "", emailnorm.RegistrableDomain("not-an-address"))
}

func TestNormalize_ErrorsAreSentinels(t *testing.T) {
	_, err := emailnorm.Normalize("alice@exa mple.com")
	assert.ErrorIs(t, err, emailnorm.ErrInvalidDomain)
	_, err = emailnorm.Normalize("alice@pаypal.com") // Cyrillic а
	assert.ErrorIs(t, err, emailnorm.ErrMixedScript)
}
