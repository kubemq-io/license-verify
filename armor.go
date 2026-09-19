package licenseverify

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Armor framing for offline license files.
const (
	ArmorBegin = "-----BEGIN KUBEMQ LICENSE-----"
	ArmorEnd   = "-----END KUBEMQ LICENSE-----"
)

const armorLineWidth = 64

// Armor wraps a compact JWS in the KUBEMQ LICENSE envelope: the standard
// base64 of the JWS bytes, wrapped at 64 columns, framed by ArmorBegin and
// ArmorEnd on their own lines, LF line endings, trailing newline.
func Armor(jws string) []byte {
	enc := base64.StdEncoding.EncodeToString([]byte(jws))
	var sb strings.Builder
	sb.Grow(len(enc) + len(enc)/armorLineWidth + len(ArmorBegin) + len(ArmorEnd) + 4)
	sb.WriteString(ArmorBegin)
	sb.WriteByte('\n')
	for len(enc) > armorLineWidth {
		sb.WriteString(enc[:armorLineWidth])
		sb.WriteByte('\n')
		enc = enc[armorLineWidth:]
	}
	sb.WriteString(enc)
	sb.WriteByte('\n')
	sb.WriteString(ArmorEnd)
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// Dearmor returns the compact JWS inside a KUBEMQ LICENSE armor, or the input
// itself when it is already a bare compact JWS (three dot-separated base64url
// segments). Anything else — including any other or legacy armor header —
// fails with ErrArmor. Dearmor does not verify the token.
func Dearmor(data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", fmt.Errorf("%w: empty input", ErrArmor)
	}
	if !strings.HasPrefix(text, "-----") {
		if !looksLikeCompactJWS(text) {
			return "", fmt.Errorf("%w: not an armored file nor a compact JWS", ErrArmor)
		}
		return text, nil
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	if lines[0] != ArmorBegin {
		return "", fmt.Errorf("%w: unexpected header %q", ErrArmor, lines[0])
	}
	last := lines[len(lines)-1]
	if len(lines) < 3 || last != ArmorEnd {
		return "", fmt.Errorf("%w: missing or unexpected footer", ErrArmor)
	}
	body := strings.Join(lines[1:len(lines)-1], "")
	raw, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("%w: body: %v", ErrArmor, err)
	}
	jws := string(raw)
	if !looksLikeCompactJWS(jws) {
		return "", fmt.Errorf("%w: body is not a compact JWS", ErrArmor)
	}
	return jws, nil
}

// looksLikeCompactJWS reports whether s is header.payload.signature with each
// segment non-empty and drawn from the base64url alphabet (no padding).
func looksLikeCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
