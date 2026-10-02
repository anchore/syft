package internal

import (
	"path"
	"strings"
)

// Rel returns a forward-slash relative path from base to target, equivalent to
// filepath.Rel but for already-cleaned, forward-slash paths. Both base and target
// should be absolute-style (leading "/") paths. The result preserves ".." segments
// for targets that escape the base, so symlinks whose real path lives outside the
// scanned base directory are represented correctly (e.g. "../foo").
func splitPath(p string) []string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func Rel(base, target string) string {
	if base == target {
		return "."
	}

	baseSegs := splitPath(base)
	targSegs := splitPath(target)

	// Find the length of the common prefix.
	n := 0
	for n < len(baseSegs) && n < len(targSegs) && baseSegs[n] == targSegs[n] {
		n++
	}

	// Build up-segments for any base segments beyond the common prefix.
	up := make([]string, len(baseSegs)-n)
	for i := range up {
		up[i] = ".."
	}

	result := strings.Join(append(up, targSegs[n:]...), "/")
	if result == "" {
		return "."
	}
	return result
}

// ConvertAbsoluteToRelative strips the leading "/" from an absolute path.
// If the path is already relative it is returned unchanged.
func ConvertAbsoluteToRelative(absPath string) string {
	if !path.IsAbs(absPath) {
		return absPath
	}
	return strings.TrimPrefix(absPath, "/")
}
