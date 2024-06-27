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

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func SplitAny(s string, seps string) []string {
	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}
	result := strings.FieldsFunc(s, splitter)
	if len(result) == 0 {
		return []string{s}
	}
	return result
}
