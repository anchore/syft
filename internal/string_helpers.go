package internal

import "strings"

// HasAnyOfPrefixes returns an indication if the given string has any of the given prefixes.
func HasAnyOfPrefixes(input string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(input, prefix) {
			return true
		}
	}

	return false
}

func TruncateMiddleEllipsis(input string, maxLen int) string {
	if len(input) <= maxLen {
		return input
	}
	return input[:maxLen/2] + "..." + input[len(input)-(maxLen/2):]
}
