package cataloging

import "strings"

// anyDepthPrefix marks the one pattern shape that reaches inside an archive.
//
// A directory source accepts three shapes (directorysource.GetDirectoryExclusionFunctions):
//
//	./x    a path at the scan root
//	*/x    a path exactly one level below the scan root - `*` matches one segment and no separator,
//	       so it matches a/x but neither x nor a/b/x
//	**/x   x at any depth, the scan root included
//
// Only the third is depth-independent, so only it means the same thing re-rooted at an archive's
// extraction directory. The rule holds for image sources too, which do not validate these shapes.
const anyDepthPrefix = "**/"

// ArchiveExclusionPatterns returns the subset of the scan's exclusion patterns that reach inside an
// archive, normalized for matching. A pattern's own shape decides: see anyDepthPrefix.
//
// The trailing slash is trimmed as the directory source trims it: it reads as "a directory" but
// doublestar.Match discards it, so a pattern keeping it matches nothing (issue #4839).
func ArchiveExclusionPatterns(exclusions []string) []string {
	var out []string
	for _, exclusion := range exclusions {
		if !strings.HasPrefix(exclusion, anyDepthPrefix) {
			continue
		}
		out = append(out, strings.TrimSuffix(exclusion, "/"))
	}
	return out
}
