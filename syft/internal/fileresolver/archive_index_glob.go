package fileresolver

import (
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	syftindex "github.com/anchore/syft/internal/index"
	"github.com/anchore/syft/syft/file"
)

// The search here is ported from the dirscan prototype the key-split index came from. The shape is
// the prototype's: walk the pattern segment by segment, and wherever a segment fixes enough text,
// answer it from an index instead of from the children of the directory the walk has reached.
//
// Three deliberate departures from the prototype:
//
//   - doublestar decides every segment the indexes cannot answer, rather than the prototype's
//     hand-built regex. syft's globs are doublestar's dialect, and a segment carrying `?` or a `[...]`
//     class has to mean there what it means everywhere else in syft.
//   - a pattern the prototype panics on is answered instead: an embedded `**` (`a**b`) is matched as
//     an ordinary segment, and a trailing `**` collects everything below.
//   - alternations are expanded over the whole pattern rather than one segment at a time, and on `,`
//     rather than the prototype's `|`. syft's catalogers write `{status,status.d/**}`, where the
//     alternatives carry separators, and `|` is not an alternation to doublestar at all.
const (
	anyDir   = "**"
	sep      = "/"
	wildcard = '*'
)

// FilesByGlob returns the files matching any of the patterns.
//
// Patterns are archive-relative. A leading slash is the archive's own root rather than a filesystem
// root, so `/META-INF/*` and `META-INF/*` name the same entries.
func (r *ArchiveIndex) FilesByGlob(patterns ...string) ([]file.Location, error) {
	found := map[*indexNode]struct{}{}
	for _, pattern := range patterns {
		// braces are expanded before splitting into segments, since an alternative may carry its own
		// separators: `{status,status.d/**}` is one segment and two, and splitting first would cut the
		// group in half. Past maxAlternatives the pattern is searched as written - see segmentProvider.
		alternatives, ok := expandBraces(pattern)
		if !ok {
			alternatives = []string{pattern}
		}
		for _, alternative := range alternatives {
			trimmed := strings.Trim(alternative, sep)
			if trimmed == "" {
				continue
			}
			r.search(found, r.root, strings.Split(trimmed, sep), nil, true)
		}
	}

	out := make([]file.Location, 0, len(found))
	for target, access := range collapseToOnePathPerFile(found) {
		out = append(out, r.accessedLocation(target, access))
	}
	// location order decides how a cataloger merges its findings, and the search accumulates into a map.
	// This sort is only for a stable answer; which path names each file is settled by preferredAccess.
	sort.Slice(out, func(i, j int) bool { return out[i].RealPath < out[j].RealPath })
	return out, nil
}

// collapseToOnePathPerFile reduces the matched nodes to one path per file, keyed by the node holding
// that file's content.
//
// Several paths can name one file - a link and its target, or two links to it - and a resolver answers
// with one of them (see file.Resolver: "if multiple paths to the same file are found, the best single
// match should be returned"). A dangling link names no content, so it stands alone under its own path.
func collapseToOnePathPerFile(found map[*indexNode]struct{}) map[*indexNode]*indexNode {
	best := make(map[*indexNode]*indexNode, len(found))
	for node := range found {
		target := node.target
		if target == nil {
			target = node
		}
		current, seen := best[target]
		if !seen || preferredAccess(node, current, target) == node {
			best[target] = node
		}
	}
	return best
}

// preferredAccess picks which of two paths to one file the answer carries: the path that is the file
// itself, and otherwise the lower-sorting one.
//
// Both clauses read only the candidates, never their arrival order, so the winner is stable across
// runs regardless of map iteration order or how results are later sorted.
func preferredAccess(a, b, target *indexNode) *indexNode {
	switch {
	case a == target:
		return a
	case b == target:
		return b
	case a.path < b.path:
		return a
	}
	return b
}

// childProvider yields the nodes of one directory that a segment can reach. A provider may ignore the
// directory it is handed and answer from a global index instead, which is how `**` is skipped over.
type childProvider func(parent *indexNode) []*indexNode

// search matches segments against the tree from parent, collecting every file the pattern reaches.
//
// visited is how `**` avoids reporting the same file twice when the directories it expands to overlap,
// and checkVisited is false on the recursions that are not a descent - an alternation being retried
// against the same directory, or `**` matching the directory it starts from.
func (r *ArchiveIndex) search(found map[*indexNode]struct{}, parent *indexNode, segments []string, visited []*indexNode, checkVisited bool) {
	if len(segments) == 0 {
		return
	}

	if checkVisited {
		for _, seen := range visited {
			if seen == parent {
				return
			}
		}
		visited = append(visited, parent)
	}

	segment := segments[0]

	if segment == anyDir {
		r.searchAnyDir(found, parent, segments, visited)
		return
	}

	provider := r.segmentProvider(segment)

	if len(segments) == 1 {
		for _, child := range provider(parent) {
			keepFile(found, child)
		}
		return
	}

	for _, child := range provider(parent) {
		if !child.isDir {
			continue
		}
		r.search(found, child, segments[1:], visited, true)
	}
}

// searchAnyDir handles a `**` segment.
//
// `**` matches the directory it sits at and every directory below it, so the general answer is to
// re-run what follows from each of those. The index is what makes that avoidable: when the pattern
// starts with `**`, the segment after it can often be looked up by name across the whole archive,
// which reaches the same directories - or, at the end of a pattern, the same files - without walking.
func (r *ArchiveIndex) searchAnyDir(found map[*indexNode]struct{}, parent *indexNode, segments []string, visited []*indexNode) {
	rest := segments[1:]

	if len(rest) == 0 {
		// a pattern ending in `**`: everything below here. The prototype rejects this shape; syft's
		// catalogers do write it.
		r.collect(found, parent)
		return
	}

	// The segment after a `**` is looked up across the whole archive, then confined to what sits below
	// parent. The global lookup is what the name indexes key on; the filter is what lets a `**` appear
	// anywhere in the pattern, not just as the leading segment.
	//
	// This matters for split patterns: `/{usr,opt}/**/*.jar` becomes `/usr/**/*.jar` and `/opt/**/*.jar`,
	// each reaching its `**` with a directory already selected, where the prototype would walk every
	// directory beneath it.
	//
	// Alternations are already expanded by FilesByGlob, so `{go,go.exe}` reaches here as two exact names.
	if len(rest) == 1 {
		// `**/<file>`, the shape most cataloger globs take
		if nodes, ok := r.byName(&r.fileNames, rest[0]); ok {
			for _, node := range nodes {
				if under(node, parent) {
					keepFile(found, node)
				}
			}
			return
		}
	} else if nodes, ok := r.byName(&r.dirNames, rest[0]); ok {
		// `**/<dir>/<more>`: the directory segment is looked up across the archive, and the search
		// continues from each match with both segments consumed
		for _, node := range nodes {
			if under(node, parent) {
				r.search(found, node, rest[1:], visited, true)
			}
		}
		return
	}

	// `**` matches this directory and every directory beneath it
	r.search(found, parent, rest, visited, false)
	for _, dir := range r.dirsBeneath(parent) {
		r.search(found, dir, rest, visited, true)
	}
}

func dedupeNodes(nodes []*indexNode) []*indexNode {
	if len(nodes) < 2 {
		return nodes
	}
	seen := make(map[*indexNode]struct{}, len(nodes))
	out := nodes[:0]
	for _, node := range nodes {
		if _, dup := seen[node]; dup {
			continue
		}
		seen[node] = struct{}{}
		out = append(out, node)
	}
	return out
}

// byName answers one segment from a global name index, reporting false when the segment fixes too
// little for any lookup to reach every name it could match.
//
// Three shapes the index answers outright: an exact name, a single leading `*`, and a single trailing
// `*`. Everything else goes to byNameNarrowed, which either reduces the segment to a set of those or
// narrows by the literal text it fixes and lets doublestar decide.
func (r *ArchiveIndex) byName(idx *syftindex.PrefixSuffix[[]*indexNode], segment string) ([]*indexNode, bool) {
	if strings.Contains(segment, anyDir) {
		// `a**b` crosses directories, so no base-name lookup can answer it
		return nil, false
	}
	if strings.ContainsAny(segment, nonWildcardMeta) {
		// not a literal-with-one-`*`, so the plain lookups below would read the metacharacters as text
		return r.byNameNarrowed(idx, segment)
	}

	first := strings.IndexRune(segment, wildcard)
	last := strings.LastIndexByte(segment, byte(wildcard))

	switch {
	case first < 0:
		// an exact name, e.g. **/pom.properties
		return idx.Get(segment), true
	case first == 0 && last == 0:
		// `*something`, e.g. **/*.jar - what the reverse index is keyed for. A lone `*` gives the empty
		// suffix, which reaches every name, and that is the right answer for `**/*`.
		return flattenNodes(idx.BySuffix(segment[1:])), true
	case last == len(segment)-1 && first == last:
		// `something*`, e.g. **/pom*
		return flattenNodes(idx.ByPrefix(segment[:len(segment)-1])), true
	}

	// anything else - a `?`, a class, a wildcard in the middle - is not a lookup on its own, but the
	// literal text it fixes still narrows one
	return r.byNameNarrowed(idx, segment)
}

// byNameNarrowed answers a segment the three shapes above cannot, by narrowing the index to a
// candidate set and letting doublestar decide over it. It reports false when the segment fixes nothing
// to narrow by, which leaves the caller to walk.
//
// Two ways in. A segment whose only metacharacters are alternations and classes denotes a finite set
// of names, so it reduces to exact lookups and doublestar is not needed at all. Anything else is
// narrowed by the literal text it fixes at its head or tail - `libstd-????????????????.so` fixes
// "libstd-" and ".so" - and doublestar runs over what that leaves.
func (r *ArchiveIndex) byNameNarrowed(idx *syftindex.PrefixSuffix[[]*indexNode], segment string) ([]*indexNode, bool) {
	if lookups := enumerateLookups(segment); len(lookups) > 0 {
		// each lookup is exactly its alternative: `*` stands for any run of characters and a base name
		// holds no separator for it to stop at
		return byLookups(idx, lookups), true
	}

	candidates, ok := r.narrowByBounds(idx, segment)
	if !ok {
		return nil, false
	}
	return matchingNodes(candidates, segment), true
}

func byLookups(idx *syftindex.PrefixSuffix[[]*indexNode], lookups []nameLookup) []*indexNode {
	var out []*indexNode
	for _, lookup := range lookups {
		switch lookup.kind {
		case segExact:
			out = append(out, idx.Get(lookup.literal)...)
		case segPrefix:
			out = append(out, flattenNodes(idx.ByPrefix(lookup.literal))...)
		case segSuffix:
			out = append(out, flattenNodes(idx.BySuffix(lookup.literal))...)
		}
	}
	if len(lookups) < 2 {
		return out
	}
	// alternatives can overlap, e.g. `{lib,l}*` looks up "lib" and "l"
	return dedupeNodes(out)
}

// boundProbe is how many names a bound may reach before it is treated as the broad side, capping what
// the probe below can waste: a side that gives up costs this much, not the size of its full result.
//
// Sized for what a cataloger's glob seeks, not what an archive holds. A bound reaching more names than
// this is not narrowing much.
const boundProbe = 64

// narrowByBounds returns the nodes whose name carries one of the literal bounds the segment fixes, or
// false when it fixes nothing to look up by.
//
// A segment fixing text at both ends has two possible lookups, and the text alone does not say which
// is selective: among one `libstd-<hash>.so` beside 1,500 `libstd-NNNN.a`, "libstd-" reaches all 1,501
// and ".so" reaches one, so the longer literal is the worse lookup.
//
// The selective side is found by running one lookup bounded: one that completes is both the answer and
// proof it was cheap; one that gives up costs only boundProbe. So choosing costs the probe, not the
// broad side's full result.
func (r *ArchiveIndex) narrowByBounds(idx *syftindex.PrefixSuffix[[]*indexNode], segment string) ([]*indexNode, bool) {
	prefixes, suffixes := segmentBounds(segment)

	switch {
	case len(prefixes) == 0 && len(suffixes) == 0:
		return nil, false
	case len(suffixes) == 0:
		return gather(prefixes, idx.ByPrefix), true
	case len(prefixes) == 0:
		return gather(suffixes, idx.BySuffix), true
	}

	// the tail first: a name's extension is usually the more selective end of it
	if nodes, ok := gatherUpTo(suffixes, idx.BySuffixUpTo); ok {
		return nodes, true
	}
	if nodes, ok := gatherUpTo(prefixes, idx.ByPrefixUpTo); ok {
		return nodes, true
	}

	// neither end narrows to less than the probe, so nothing distinguishes them and doublestar has the
	// same work either way
	return gather(prefixes, idx.ByPrefix), true
}

// gatherUpTo runs a set of bounds under one shared probe budget, reporting false as soon as they
// reach past it. What it returns on false is partial and is discarded.
func gatherUpTo(values []string, lookup func(string, int) ([][]*indexNode, bool)) ([]*indexNode, bool) {
	var out []*indexNode
	for _, value := range values {
		groups, complete := lookup(value, boundProbe)
		if !complete {
			return nil, false
		}
		out = append(out, flattenNodes(groups)...)
		if len(out) > boundProbe {
			// one name per key, but a name repeats across directories - the budget is on what comes back
			return nil, false
		}
	}
	if len(values) < 2 {
		return out, true
	}
	return dedupeNodes(out), true
}

func gather(values []string, lookup func(string) [][]*indexNode) []*indexNode {
	var out []*indexNode
	for _, value := range values {
		out = append(out, flattenNodes(lookup(value))...)
	}
	if len(values) < 2 {
		return out
	}
	return dedupeNodes(out)
}

// matchingNodes keeps the candidates whose name the segment actually matches: the bounds narrow,
// doublestar decides.
func matchingNodes(candidates []*indexNode, segment string) []*indexNode {
	var out []*indexNode
	for _, node := range candidates {
		if ok, err := doublestar.Match(segment, node.name); err == nil && ok {
			out = append(out, node)
		}
	}
	return out
}

// nonWildcardMeta are the glob metacharacters the index lookups cannot reason about. A lookup reads a
// segment as literal text around at most one `*`, so a segment carrying any of these goes to
// doublestar rather than being looked up as a literal name that matches nothing.
const nonWildcardMeta = `?[]{}\`

// segmentProvider returns how to reach the children of a directory that one segment matches, choosing
// the narrowest answer the segment allows.
func (r *ArchiveIndex) segmentProvider(segment string) childProvider {
	if strings.ContainsAny(segment, nonWildcardMeta) || strings.Contains(segment, anyDir) {
		return narrowedChildren(segment)
	}

	first := strings.IndexRune(segment, wildcard)
	switch {
	case first < 0:
		// an exact name: one lookup in this directory's index
		return func(parent *indexNode) []*indexNode {
			if child := parent.children.Get(segment); child != nil {
				return []*indexNode{child}
			}
			return nil
		}
	case segment == string(wildcard):
		return func(parent *indexNode) []*indexNode { return parent.childList }
	case first == len(segment)-1:
		// `name*`, which this directory's index answers by prefix
		prefix := segment[:len(segment)-1]
		return func(parent *indexNode) []*indexNode { return parent.children.ByPrefix(prefix) }
	}

	return narrowedChildren(segment)
}

// narrowedChildren is the fallback, narrowing a directory's children as far as the segment allows
// before doublestar sees them.
//
// A directory's children are indexed forwards only, so unlike the global indexes only a leading bound
// is usable here - which is why a segment that reduces to a set of exact and prefix lookups is worth
// detecting separately, and why `*tail` falls back to comparing each child.
func narrowedChildren(segment string) childProvider {
	if lookups := enumerateLookups(segment); len(lookups) > 0 {
		return func(parent *indexNode) []*indexNode {
			return childrenByLookups(parent, lookups)
		}
	}

	prefixes, _ := segmentBounds(segment)
	if len(prefixes) == 0 {
		return matchingChildren(segment, func(parent *indexNode) []*indexNode { return parent.childList })
	}
	return matchingChildren(segment, func(parent *indexNode) []*indexNode {
		var out []*indexNode
		for _, prefix := range prefixes {
			out = append(out, parent.children.ByPrefix(prefix)...)
		}
		if len(prefixes) < 2 {
			return out
		}
		return dedupeNodes(out)
	})
}

// childrenByLookups answers a segment that reduces to a finite set of lookups. Each lookup is exactly
// its alternative, so nothing here needs doublestar - see byLookups.
func childrenByLookups(parent *indexNode, lookups []nameLookup) []*indexNode {
	var out []*indexNode
	for _, lookup := range lookups {
		switch lookup.kind {
		case segExact:
			if child := parent.children.Get(lookup.literal); child != nil {
				out = append(out, child)
			}
		case segPrefix:
			out = append(out, parent.children.ByPrefix(lookup.literal)...)
		case segSuffix:
			// children are indexed forwards only, so a fixed tail is compared per child
			for _, child := range parent.childList {
				if strings.HasSuffix(child.name, lookup.literal) {
					out = append(out, child)
				}
			}
		}
	}
	if len(lookups) < 2 {
		return out
	}
	return dedupeNodes(out)
}

// matchingChildren runs doublestar over whatever candidates narrows down to.
func matchingChildren(segment string, narrow childProvider) childProvider {
	return func(parent *indexNode) []*indexNode {
		var out []*indexNode
		for _, child := range narrow(parent) {
			if ok, err := doublestar.Match(segment, child.name); err == nil && ok {
				out = append(out, child)
			}
		}
		return out
	}
}

// under reports whether node sits strictly below dir, which is what confines a global name lookup to
// the subtree a `**` is standing in.
//
// Paths are archive-rooted and cleaned, so this is a prefix test with the separator checked: without
// it "/usrlocal/x" would read as below "/usr". The archive root is above everything.
func under(node, dir *indexNode) bool {
	if dir.path == "/" {
		return true
	}
	return len(node.path) > len(dir.path) &&
		node.path[len(dir.path)] == '/' &&
		strings.HasPrefix(node.path, dir.path)
}

// keepFile records a node if it is a file this archive actually holds. Directories are never a glob's
// answer, and a synthesized directory has no entry to read.
func keepFile(found map[*indexNode]struct{}, node *indexNode) {
	if node == nil || node.isDir || node.entry == nil {
		return
	}
	found[node] = struct{}{}
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

// collect records every file at or below a node.
func (r *ArchiveIndex) collect(found map[*indexNode]struct{}, node *indexNode) {
	for _, child := range node.childList {
		if child.isDir {
			r.collect(found, child)
			continue
		}
		keepFile(found, child)
	}
}

func flattenNodes(groups [][]*indexNode) []*indexNode {
	var out []*indexNode
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}
