package archive

import (
	"path"
	"strings"
	"sync"
	"sync/atomic"

	syftindex "github.com/anchore/syft/internal/index"
)

// A glob is parsed once into segments, cached by pattern since catalogers ask the same few hundred
// globs of every archive. A brace group inside a segment, `g{o,o.exe}`, makes that segment a set of
// alternatives, each looked up on its own; only a group spanning `/` expands the whole pattern.
// The literal text at either end of every alternative is looked up in the base-name indexes: files
// for the last segment, directories for the rest. The smallest set found is the candidate set, and
// each candidate is verified segment by segment up its parent chain. Only a pattern with no literal
// text anywhere falls back to every file.

// globSegment is one `/`-delimited piece of a pattern.
type globSegment struct {
	alts []globAlt // the texts a name may match; one unless the segment has a brace group
	any  bool      // `**`: zero or more directories

	// indexed reports every alternative has literal text to look up; exact that every lookup is the
	// whole answer for its alternative: a plain name, `prefix*` or `*suffix`
	indexed, exact bool
}

// globAlt is one alternative text of a segment.
type globAlt struct {
	text string // ready for path.Match

	// prefix and suffix are the literal text before the first and after the last metacharacter, the
	// necessary conditions a name index can check. For a plain text prefix is the whole of it.
	prefix, suffix string
	plain          bool
}

// maxCachedGlobs bounds the parse cache, which is sized for the catalogers' own patterns.
const maxCachedGlobs = 4096

var (
	parsedGlobs     sync.Map // pattern -> [][]globSegment
	parsedGlobCount atomic.Int64
)

// parseGlob returns the segment lists a pattern spells out: one, unless a brace group spans `/`.
// Leading slashes are dropped since paths are archive-relative; an empty pattern has none.
func parseGlob(pattern string) [][]globSegment {
	if cached, ok := parsedGlobs.Load(pattern); ok {
		return cached.([][]globSegment)
	}
	var out [][]globSegment
	if braceSpansSeparator(pattern) {
		for _, alternative := range expandBraces(pattern) {
			out = append(out, parseSegments(alternative))
		}
	} else if segments := parseSegments(pattern); segments != nil {
		out = [][]globSegment{segments}
	}
	if parsedGlobCount.Add(1) <= maxCachedGlobs {
		parsedGlobs.Store(pattern, out)
	}
	return out
}

func parseSegments(pattern string) []globSegment {
	pattern = strings.TrimLeft(pattern, "/")
	if pattern == "" {
		return nil
	}
	var segments []globSegment
	for _, text := range strings.Split(pattern, "/") {
		s := globSegment{any: text == "**", indexed: true, exact: true}
		if !s.any {
			texts := []string{text}
			if strings.IndexByte(text, '{') >= 0 {
				texts = expandBraces(text)
			}
			for _, t := range texts {
				a := globAlt{text: strings.ReplaceAll(t, "[!", "[^")} // doublestar negation, for path.Match
				a.prefix, a.suffix, a.plain = literalEnds(a.text)
				s.indexed = s.indexed && (a.prefix != "" || a.suffix != "")
				s.exact = s.exact && (a.plain || a.text == a.prefix+"*" || a.text == "*"+a.suffix)
				s.alts = append(s.alts, a)
			}
		}
		segments = append(segments, s)
	}
	return segments
}

// braceSpansSeparator reports whether a `/` sits inside a brace group, so the group's alternatives
// have different segment counts.
func braceSpansSeparator(pattern string) bool {
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			depth = max(depth-1, 0)
		case '/':
			if depth > 0 {
				return true
			}
		}
	}
	return false
}

// literalEnds returns the literal text before the first metacharacter and after the last one, and
// whether there were none. A character class is one metacharacter however long, as is an escape pair.
func literalEnds(seg string) (prefix, suffix string, plain bool) {
	first, lastEnd := -1, -1
	mark := func(start, end int) {
		if first < 0 {
			first = start
		}
		lastEnd = end
	}
	for i := 0; i < len(seg); {
		switch seg[i] {
		case '*', '?':
			mark(i, i+1)
			i++
		case '\\':
			mark(i, min(i+2, len(seg)))
			i += 2
		case '[':
			// a `]` right after `[` or `[^` is a member of the class, not its end
			j := i + 1
			if j < len(seg) && seg[j] == '^' {
				j++
			}
			if j < len(seg) && seg[j] == ']' {
				j++
			}
			end := strings.IndexByte(seg[j:], ']')
			if end < 0 {
				mark(i, len(seg))
				i = len(seg)
			} else {
				mark(i, j+end+1)
				i = j + end + 1
			}
		default:
			i++
		}
	}
	if first < 0 {
		return seg, "", true
	}
	return seg[:first], seg[lastEnd:], false
}

// expandBraces returns every pattern a brace group spells out, nested groups included. A pattern
// without a complete group is returned as is.
func expandBraces(pattern string) []string {
	start, depth := -1, 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 {
				var out []string
				for _, alt := range splitAlternatives(pattern[start+1 : i]) {
					out = append(out, expandBraces(pattern[:start]+alt+pattern[i+1:])...)
				}
				return out
			}
		}
	}
	return []string{pattern}
}

// splitAlternatives splits a brace group's body on the commas at its top level.
func splitAlternatives(body string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, body[last:i])
				last = i + 1
			}
		}
	}
	return append(out, body[last:])
}

// lookup finds the nodes a segment admits in a base-name index: for each alternative the smaller of
// what its prefix and suffix find, or the name itself when it is plain. It reports false for a
// segment with an alternative that has no literal text, which admits every name.
func lookup(idx *syftindex.PrefixSuffix[[]*node], s globSegment) ([]*node, bool) {
	if !s.indexed {
		return nil, false
	}
	var out []*node
	for _, a := range s.alts {
		switch {
		case a.plain:
			out = append(out, idx.Get(a.text)...)
		case a.suffix == "":
			out = append(out, flatten(idx.ByPrefix(a.prefix))...)
		case a.prefix == "":
			out = append(out, flatten(idx.BySuffix(a.suffix))...)
		default:
			byPrefix, bySuffix := flatten(idx.ByPrefix(a.prefix)), flatten(idx.BySuffix(a.suffix))
			if len(bySuffix) < len(byPrefix) {
				byPrefix = bySuffix
			}
			out = append(out, byPrefix...)
		}
	}
	return out, true
}

func flatten(groups [][]*node) []*node {
	var out []*node
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// exactByName reports whether the pattern is `**/<segment>` with a segment the file-name index answers
// completely, so its lookup needs no verification.
func exactByName(segments []globSegment) bool {
	return len(segments) == 2 && segments[0].any && segments[1].exact
}

// narrowEnough is a candidate count small enough that looking for a smaller set is not worth it.
const narrowEnough = 64

// globCandidates returns the files a pattern can match, and whether they are exactly the answer.
func (r *Resolver) globCandidates(segments []globSegment) (candidates []*node, exact bool) {
	last := segments[len(segments)-1]
	best := r.files
	if !last.any {
		if files, ok := lookup(&r.names, last); ok {
			if exactByName(segments) || len(files) <= narrowEnough {
				return files, exactByName(segments)
			}
			best = files
		}
	}

	// a directory segment narrows to what lies under the directories it names; take it only when
	// that is smaller than what the file name gave, stopping the walk as soon as it is not
	for _, s := range segments[:len(segments)-1] {
		if s.any {
			continue
		}
		dirs, ok := lookup(&r.dirs, s)
		if !ok || len(dirs) >= len(best) {
			continue
		}
		if under := filesUnder(dirs, len(best)-1); under != nil {
			best = under
		}
	}
	return best, false
}

// filesUnder collects the files anywhere beneath the given directories, or nil once more than limit
// are found.
func filesUnder(dirs []*node, limit int) []*node {
	var out []*node
	stack := append([]*node(nil), dirs...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, child := range n.children {
			if child.isDir {
				stack = append(stack, child)
				continue
			}
			if child.header != nil {
				if len(out) >= limit {
					return nil
				}
				out = append(out, child)
			}
		}
	}
	return out
}

// matchNode reports whether the segments match the node's path, read up its parent chain.
func matchNode(segments []globSegment, n *node) (bool, error) {
	var buf [16]string
	names := buf[:0]
	for m := n; m.parent != nil; m = m.parent {
		names = append(names, m.name)
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	return matchSegments(segments, names)
}

// matchSegments matches segments against path components. The segments after the last `**` sit at
// fixed positions from the end, so they are matched against the tail first, which settles the common
// `**/x` in one comparison; what remains ends in `**` and is matched greedily, backing up to the most
// recent `**` on a mismatch.
func matchSegments(segments []globSegment, names []string) (bool, error) {
	lastAny := -1
	for i, s := range segments {
		if s.any {
			lastAny = i
		}
	}
	tail := segments[lastAny+1:]
	if len(names) < len(tail) {
		return false, nil
	}
	names, tailNames := names[:len(names)-len(tail)], names[len(names)-len(tail):]
	for i, s := range tail {
		if ok, err := s.match(tailNames[i]); !ok || err != nil {
			return false, err
		}
	}
	if lastAny < 0 {
		return len(names) == 0, nil
	}

	segments = segments[:lastAny+1]
	si, ni := 0, 0
	starSeg, starName := -1, 0
	for ni < len(names) {
		if si < len(segments) {
			if segments[si].any {
				starSeg, starName = si, ni
				si++
				continue
			}
			ok, err := segments[si].match(names[ni])
			if err != nil {
				return false, err
			}
			if ok {
				si++
				ni++
				continue
			}
		}
		if starSeg < 0 {
			return false, nil
		}
		starName++
		si, ni = starSeg+1, starName
	}
	for ; si < len(segments); si++ {
		if !segments[si].any {
			return false, nil
		}
	}
	return true, nil
}

// match reports whether any of the segment's alternatives matches a name.
func (s globSegment) match(name string) (bool, error) {
	for _, a := range s.alts {
		if ok, err := path.Match(a.text, name); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}
