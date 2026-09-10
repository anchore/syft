package fileresolver

import (
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/file"
)

const (
	anyDir   = "**"
	wildcard = '*'
)

// FilesByGlob returns the files matching any of the patterns.
//
// The walk is segment by segment, with one deliberate shortcut: a pattern that begins `**/` and whose
// remainder is a single segment is answered from the global base-name index instead of by descending
// the tree. That covers `**/*.jar`, `**/pom.properties` and `**/*pom.xml` - which is most of what
// syft's catalogers ask for - and turns "match every path in this archive" into a lookup keyed on the
// name.
//
// Patterns are archive-relative. A leading slash is not a filesystem root here, it is the archive's
// own root, so `/META-INF/*` and `META-INF/*` name the same entries - and `/*` names the entries at
// the top of the archive, which is what the tar-backed resolver could not match at all.
func (r *ArchiveIndex) FilesByGlob(patterns ...string) ([]file.Location, error) {
	seen := map[string]struct{}{}
	var out []file.Location

	keep := func(node *indexNode) {
		if node.isDir || node.entry == nil {
			return
		}
		if _, dup := seen[node.path]; dup {
			return
		}
		seen[node.path] = struct{}{}
		out = append(out, r.location(node))
	}

	for _, pattern := range patterns {
		segments := splitPattern(pattern)
		if len(segments) == 0 {
			continue
		}
		if nodes, ok := r.byNameIndex(segments); ok {
			for _, node := range nodes {
				keep(node)
			}
			continue
		}
		r.match(r.root, segments, keep)
	}

	// ordered for the same reason every other answer here is: what a cataloger is handed in what order
	// decides how its findings merge, and the index's own traversal order is a map's
	sort.Slice(out, func(i, j int) bool { return out[i].RealPath < out[j].RealPath })
	return out, nil
}

// splitPattern turns a glob into its segments, dropping the leading and trailing separators that
// distinguish "rooted at the archive" from "relative to it" - inside one archive there is no
// difference.
func splitPattern(pattern string) []string {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// byNameIndex answers the `**/<one segment>` shapes from the global file-name index, and reports false
// for anything else so the caller falls back to the walk.
//
// Only the forms the index can answer exactly are taken: a suffix match (`*foo`), a prefix match
// (`foo*`), and an exact name. A segment with a wildcard in the middle would need every name anyway,
// so it goes to the walk rather than pretending.
func (r *ArchiveIndex) byNameIndex(segments []string) ([]*indexNode, bool) {
	if len(segments) != 2 || segments[0] != anyDir {
		return nil, false
	}
	name := segments[1]
	if strings.Contains(name, anyDir) {
		return nil, false
	}

	first := strings.IndexRune(name, wildcard)
	last := strings.LastIndexByte(name, byte(wildcard))

	switch {
	case first < 0:
		// an exact name, e.g. **/pom.properties
		return flattenNodes(r.fileNames.Get(name)), true
	case first == 0 && last == 0 && len(name) > 1:
		// *something, e.g. **/*.jar - the reverse index is keyed for exactly this
		return flattenNodes(r.fileNames.BySuffix(name[1:])...), true
	case last == len(name)-1 && first == last && len(name) > 1:
		// something*, e.g. **/pom*
		return flattenNodes(r.fileNames.ByPrefix(name[:len(name)-1])...), true
	}
	return nil, false
}

func flattenNodes(groups ...[]*indexNode) []*indexNode {
	var out []*indexNode
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// match walks the pattern's segments from a node, calling keep for every file the pattern reaches.
func (r *ArchiveIndex) match(from *indexNode, segments []string, keep func(*indexNode)) {
	if len(segments) == 0 {
		keep(from)
		return
	}

	segment := segments[0]
	rest := segments[1:]

	if segment == anyDir {
		// ** matches this directory and every directory beneath it
		if len(rest) == 0 {
			r.collect(from, keep)
			return
		}
		r.match(from, rest, keep)
		for _, dir := range r.dirsBeneath(from) {
			r.match(dir, rest, keep)
		}
		return
	}

	for _, child := range r.childrenMatching(from, segment) {
		if len(rest) == 0 {
			keep(child)
			continue
		}
		if child.isDir {
			r.match(child, rest, keep)
		}
	}
}

// childrenMatching returns the children of a node whose names match one glob segment, using the
// directory's own name index where the segment allows it.
func (r *ArchiveIndex) childrenMatching(node *indexNode, segment string) []*indexNode {
	first := strings.IndexRune(segment, wildcard)

	switch {
	case first < 0:
		// an exact name: one lookup in this directory's index
		if child := node.children.Get(segment); child != nil {
			return []*indexNode{child}
		}
		return nil
	case segment == string(wildcard):
		return node.childList
	case first == len(segment)-1:
		// name*, which the directory's index answers by prefix
		return node.children.ByPrefix(segment[:len(segment)-1])
	}

	var out []*indexNode
	for _, child := range node.childList {
		if ok, err := doublestar.Match(segment, child.name); err == nil && ok {
			out = append(out, child)
		}
	}
	return out
}

// dirsBeneath returns every directory below a node, which is what `**` has to consider when more
// pattern follows it.
func (r *ArchiveIndex) dirsBeneath(node *indexNode) []*indexNode {
	var out []*indexNode
	var walk func(*indexNode)
	walk = func(n *indexNode) {
		for _, child := range n.childList {
			if !child.isDir {
				continue
			}
			out = append(out, child)
			walk(child)
		}
	}
	walk(node)
	return out
}

// collect reports every file at or below a node.
func (r *ArchiveIndex) collect(node *indexNode, keep func(*indexNode)) {
	for _, child := range node.childList {
		if child.isDir {
			r.collect(child, keep)
			continue
		}
		keep(child)
	}
}
