package archive

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Exclusions are the scan's exclusion patterns that apply inside archives.
//
// A scan accepts three pattern shapes: `./x` anchored at the scan root, `*/x` exactly one level below
// it, and `**/x` at any depth. Only the last means the same thing when re-rooted at an archive, so
// only it reaches inside one.
type Exclusions []string

func NewExclusions(scanPatterns []string) Exclusions {
	var out Exclusions
	for _, pattern := range scanPatterns {
		if strings.HasPrefix(pattern, "**/") {
			// a trailing slash reads as "a directory" but makes doublestar match nothing (issue #4839)
			out = append(out, strings.TrimSuffix(pattern, "/"))
		}
	}
	return out
}

// Excludes reports whether an archive-relative path, or any directory above it, matches a pattern.
// Directories are checked because an archive need not list a directory before the files in it.
func (e Exclusions) Excludes(entryPath string) bool {
	for _, pattern := range e {
		for end := len(entryPath); end > 0; end = strings.LastIndexByte(entryPath[:end], '/') {
			if matched, _ := doublestar.Match(pattern, entryPath[:end]); matched {
				return true
			}
		}
	}
	return false
}
