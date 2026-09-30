package ai

import (
	"path"
	"strings"
	"unicode/utf8"
)

// pickSafeTensorsName implements the documented naming precedence chain:
func pickSafeTensorsName(nameOrPath, fallbackName string) string {
	if name := sanitizeModelName(nameOrPath); name != "" {
		return name
	}
	return fallbackName
}

// firstModelName returns the first value that sanitizes to a usable name.
func firstModelName(values []string) string {
	for _, v := range values {
		if name := sanitizeModelName(v); name != "" {
			return name
		}
	}
	return ""
}

// sanitizeModelName reduces a producer-supplied name or path (_name_or_path,
// base_model) to its last path element, capped at maxModelNameLength runes. It
// returns "" when nothing usable is left.
func sanitizeModelName(nameOrPath string) string {
	base := path.Base(strings.ReplaceAll(nameOrPath, `\`, "/"))
	switch base {
	case "/", ".", "..", "":
		return ""
	}
	if utf8.RuneCountInString(base) > maxModelNameLength {
		base = string([]rune(base)[:maxModelNameLength])
	}
	return base
}

// safeTensorsDirName returns the directory-scan naming fallback: the base name
// of the group's parent directory (the group key is already that directory).
func safeTensorsDirName(directory string) string {
	base := path.Base(directory)
	switch base {
	case "/", ".", "":
		return ""
	}
	return base
}
