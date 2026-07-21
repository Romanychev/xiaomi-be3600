package common

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// DecodeBase64IfNeeded returns the base64-decoded form of s when s looks like
// a base64 payload (e.g. a subscription blob), otherwise returns s unchanged.
func DecodeBase64IfNeeded(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.Contains(trimmed, "://") {
		return s, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(trimmed)
		if err == nil && utf8.Valid(decoded) {
			return string(decoded), nil
		}
	}
	return s, nil
}
