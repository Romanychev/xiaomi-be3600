package testlink

import (
	"strings"

	"github.com/romanychev/be3600/internal/ray2sing/common"
	"github.com/romanychev/be3600/internal/ray2sing/converter"
)

type Service struct{}

// TestLink reports whether text contains at least one valid proxy share link
// (optionally base64-encoded, e.g. a subscription blob) and no invalid ones.
func (s *Service) TestLink(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	decoded, err := common.DecodeBase64IfNeeded(text)
	if err != nil {
		return false
	}
	outbounds, err := converter.Outbounds(decoded)
	return err == nil && len(outbounds) > 0
}
