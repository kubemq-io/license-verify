package emailnorm_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubemq-io/license-verify/emailnorm"
)

type vector struct {
	Input             string  `json:"input"`
	Normalized        *string `json:"normalized"`
	Error             *string `json:"error"`
	RegistrableDomain *string `json:"registrable_domain"`
	Note              string  `json:"note,omitempty"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("vectors.json")
	require.NoError(t, err)
	var vs []vector
	require.NoError(t, json.Unmarshal(raw, &vs))
	require.GreaterOrEqual(t, len(vs), 25, "vectors.json must hold at least 25 vectors")
	return vs
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Input, func(t *testing.T) {
			require.True(t, (v.Normalized == nil) != (v.Error == nil), "exactly one of normalized/error must be set")
			got, err := emailnorm.Normalize(v.Input)
			if v.Error != nil {
				require.Error(t, err, "expected error %q", *v.Error)
				assert.Equal(t, *v.Error, emailnorm.Reason(err))
				assert.Empty(t, got)
				assert.Nil(t, v.RegistrableDomain, "error vectors carry no registrable_domain")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, *v.Normalized, got)
			require.NotNil(t, v.RegistrableDomain, "success vectors must carry registrable_domain")
			assert.Equal(t, *v.RegistrableDomain, emailnorm.RegistrableDomain(got))
			// Normalization is idempotent.
			again, err := emailnorm.Normalize(got)
			require.NoError(t, err)
			assert.Equal(t, got, again)
		})
	}
}
