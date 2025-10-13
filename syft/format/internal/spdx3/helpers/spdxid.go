package helpers

import (
	"regexp"
)

var expr = regexp.MustCompile("[^a-zA-Z0-9.-]")

// SPDX spec says SPDXID must be:
// "SPDXRef-"[idstring] where [idstring] is a unique string containing letters, numbers, ., and/or -
// https://spdx.github.io/spdx-spec/v2.3/snippet-information/
func SanitizeElementID(id string) string {
	return expr.ReplaceAllString(id, "-")
}
