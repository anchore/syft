package cataloging

import "strings"

// anyDepthPrefix marks the one pattern shape that reaches inside an archive.
//
// A directory source accepts exactly three shapes and rejects everything else outright
// (directorysource.GetDirectoryExclusionFunctions), and only this one is depth-independent:
//
//	./x    names a path at the scan root
//	*/x    names a path exactly one level below the scan root - `*` matches one segment and no
//	       separator, so it matches a/x but neither x nor a/b/x
//	**/x   names x at any depth, the scan root included
//
// The first two are measured from the scan root and describe a layout that exists only there. The
// third means the same thing wherever it is rooted, and that is what makes re-rooting it at an
// archive's extraction directory a faithful reading of it rather than a coincidence: a user who
// wrote `*/vendor` was pointing at a directory they can see, while one who wrote `**/*.rpm` was
// saying something about every tree.
//
// Image sources do not validate their patterns against these three shapes at all - that check lives
// only in the directory-source helper - but the rule needs no adjustment for them, since a pattern
// either commits to a depth or does not.
const anyDepthPrefix = "**/"

// ArchiveExclusionPatterns returns the subset of the scan's exclusion patterns that reach inside an
// archive, normalized for matching. A pattern's own shape decides: see anyDepthPrefix.
//
// The trailing slash is trimmed for the same reason the directory source trims it - it signals a
// directory to a reader but is discarded by doublestar.Match, so a pattern keeping it silently
// matches nothing (issue #4839).
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
