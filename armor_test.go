package licenseverify_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	licenseverify "github.com/kubemq-io/license-verify"
	"github.com/kubemq-io/license-verify/internal/testsign"
)

func TestArmor_RoundTrip(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(fixedNow))

	armored := licenseverify.Armor(tok)
	text := string(armored)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	assert.Equal(t, licenseverify.ArmorBegin, lines[0])
	assert.Equal(t, licenseverify.ArmorEnd, lines[len(lines)-1])
	for _, l := range lines[1 : len(lines)-1] {
		assert.LessOrEqual(t, len(l), 64)
	}
	assert.True(t, strings.HasSuffix(text, "\n"))

	got, err := licenseverify.Dearmor(armored)
	require.NoError(t, err)
	assert.Equal(t, tok, got)

	claims, err := licenseverify.Verify(got, s.Bundle(t), optsAt(fixedNow))
	require.NoError(t, err)
	assert.Equal(t, "pro", claims.Plan)
}

func TestDearmor(t *testing.T) {
	s := testsign.New(t, "k1")
	tok := s.Sign(t, testsign.BaseClaims(fixedNow))
	armored := string(licenseverify.Armor(tok))

	tests := []struct {
		name  string
		input string
		want  string
		err   bool
	}{
		{name: "bare compact JWS", input: tok, want: tok},
		{name: "bare compact JWS with surrounding whitespace", input: "  \n" + tok + "\r\n", want: tok},
		{name: "armored", input: armored, want: tok},
		{name: "armored with CRLF", input: strings.ReplaceAll(armored, "\n", "\r\n"), want: tok},
		{name: "armored with indented lines", input: strings.ReplaceAll(armored, "\n", "\n  "), want: tok},
		{name: "legacy header KUBEMQ LICENSE KEY", input: strings.Replace(armored, "BEGIN KUBEMQ LICENSE-----", "BEGIN KUBEMQ LICENSE KEY-----", 1), err: true},
		{name: "legacy header KUBEMQ KEY", input: strings.NewReplacer("BEGIN KUBEMQ LICENSE-----", "BEGIN KUBEMQ KEY-----", "END KUBEMQ LICENSE-----", "END KUBEMQ KEY-----").Replace(armored), err: true},
		{name: "wrong footer", input: strings.Replace(armored, licenseverify.ArmorEnd, "-----END KUBEMQ-----", 1), err: true},
		{name: "missing footer", input: strings.Replace(armored, licenseverify.ArmorEnd+"\n", "", 1), err: true},
		{name: "header only", input: licenseverify.ArmorBegin, err: true},
		{name: "body not base64", input: licenseverify.ArmorBegin + "\n!!!!\n" + licenseverify.ArmorEnd, err: true},
		{name: "body decodes but is not a JWS", input: licenseverify.ArmorBegin + "\naGVsbG8gd29ybGQ=\n" + licenseverify.ArmorEnd, err: true},
		{name: "empty", input: "", err: true},
		{name: "two segments", input: "abc.def", err: true},
		{name: "bare with padding chars", input: "abc.def.ghi=", err: true},
		{name: "empty segment", input: "abc..ghi", err: true},
		{name: "unknown PEM-like block", input: "-----BEGIN CERTIFICATE-----\nabcd\n-----END CERTIFICATE-----", err: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := licenseverify.Dearmor([]byte(tc.input))
			if tc.err {
				assert.ErrorIs(t, err, licenseverify.ErrArmor)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestArmor_ExactLayoutOfShortInput(t *testing.T) {
	// "a.b.c" -> base64 "YS5iLmM="
	got := string(licenseverify.Armor("a.b.c"))
	assert.Equal(t, "-----BEGIN KUBEMQ LICENSE-----\nYS5iLmM=\n-----END KUBEMQ LICENSE-----\n", got)
}
