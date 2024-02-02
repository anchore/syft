package helpers

import (
	"regexp"
)

var expr = regexp.MustCompile("[^a-zA-Z0-9.-]")

// SPDX spec says SPDXID must be:
// "SPDXRef-"[idstring] where [idstring] is a unique string containing letters, numbers, ., and/or -
func SanitizeElementID(id string) string {
	return expr.ReplaceAllString(id, "-")
}
