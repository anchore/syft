package fileresolver

import "strings"

// globMeta are the characters that end a run of literal text in a glob segment. A lone `]` or `}` is
// literal to doublestar but is treated as a stop here anyway, which only shortens a bound - a loss of
// selectivity, never of correctness. See literalBounds.
const globMeta = `*?[]{}\`

// minLiteralBound is the shortest bound worth a lookup: any non-empty fixed text, since a lookup is a
// binary search plus a walk of one contiguous run.
const minLiteralBound = 1

// maxAlternatives bounds how far brace groups and character classes are enumerated. Past it, a
// segment reports nothing to look up rather than producing exponentially many lookups.
const maxAlternatives = 32

// maxClassRange is the widest `a-z` span enumerated into members. Wider is more lookups than the scan
// it replaces.
const maxClassRange = 64

// literalBounds returns the leading and trailing literal runs any matching name must carry:
// `libstd-????????????????.so` gives "libstd-" and ".so"; `*.[jw]ar` gives "" and "ar". A side
// starting with a metacharacter fixes nothing.
//
// Bounds only filter the index; doublestar still decides. A short bound merely widens the candidate
// set, so every globMeta character stops a run to avoid dropping real matches.
func literalBounds(segment string) (prefix, suffix string) {
	first := strings.IndexAny(segment, globMeta)
	if first < 0 {
		return segment, segment
	}
	last := strings.LastIndexAny(segment, globMeta)
	return segment[:first], segment[last+1:]
}

// segmentBounds returns literal prefixes and suffixes covering every name this segment can match; a
// list is nil when the segment fixes too little on that side.
//
// Braces are expanded first, since an alternative can fix text the raw segment does not (`{go,go.exe}`
// prefixes "go" only once expanded). A side is usable only when every alternative carries a bound,
// else that alternative's matches would be lost.
func segmentBounds(segment string) (prefixes, suffixes []string) {
	alternatives, ok := expandBraces(segment)
	if !ok {
		return nil, nil
	}

	prefixes = make([]string, 0, len(alternatives))
	suffixes = make([]string, 0, len(alternatives))
	for _, alternative := range alternatives {
		prefix, suffix := literalBounds(alternative)
		if len(prefix) < minLiteralBound {
			prefixes = nil
		}
		if len(suffix) < minLiteralBound {
			suffixes = nil
		}
		if prefixes != nil {
			prefixes = append(prefixes, prefix)
		}
		if suffixes != nil {
			suffixes = append(suffixes, suffix)
		}
	}
	return dedupe(prefixes), dedupe(suffixes)
}

func dedupe(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// expandBraces enumerates the alternatives a segment's `{a,b}` groups stand for, reporting false past
// maxAlternatives.
//
// It errs toward expanding: over-expanding costs extra lookups, under-expanding costs matches. An
// unmatched `{` is left for literalBounds to stop on.
func expandBraces(segment string) ([]string, bool) {
	open, closing := braceGroup(segment)
	if open < 0 {
		return []string{segment}, true
	}

	var out []string
	for _, choice := range splitAlternatives(segment[open+1 : closing]) {
		expanded, ok := expandBraces(segment[:open] + choice + segment[closing+1:])
		if !ok || len(out)+len(expanded) > maxAlternatives {
			return nil, false
		}
		out = append(out, expanded...)
	}
	return out, true
}

// braceGroup returns the bounds of the first top-level `{...}` group, or (-1, -1) when there is none.
// Escapes and character classes are skipped, so `\{` and `[{]` are not groups.
func braceGroup(segment string) (open, closing int) {
	depth := 0
	open = -1
	for i := 0; i < len(segment); i++ {
		switch segment[i] {
		case '\\':
			i++
		case '[':
			if end := classEnd(segment, i); end >= 0 {
				i = end
			}
		case '{':
			if depth == 0 {
				open = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 {
					return open, i
				}
			}
		}
	}
	return -1, -1
}

// splitAlternatives splits the inside of a brace group on its top-level commas, leaving the commas
// of any nested group or character class alone.
func splitAlternatives(inner string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '\\':
			i++
		case '[':
			if end := classEnd(inner, i); end >= 0 {
				i = end
			}
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, inner[start:i])
				start = i + 1
			}
		}
	}
	return append(out, inner[start:])
}

// classEnd returns the index of the `]` closing the class opened at open, or -1 when it is never
// closed. A `]` first in the class, or directly after a leading negation, is a literal member.
func classEnd(segment string, open int) int {
	i := open + 1
	if i < len(segment) && (segment[i] == '!' || segment[i] == '^') {
		i++
	}
	if i < len(segment) && segment[i] == ']' {
		i++
	}
	for ; i < len(segment); i++ {
		switch segment[i] {
		case '\\':
			i++
		case ']':
			return i
		}
	}
	return -1
}

// segmentKind is what a name index can be asked for on behalf of one glob segment.
type segmentKind int

const (
	// segExact is a literal name.
	segExact segmentKind = iota
	// segPrefix is a name with a fixed head, what the forward index answers.
	segPrefix
	// segSuffix is a name with a fixed tail, what the reverse index answers.
	segSuffix
)

// nameLookup is one index lookup: an exact name, or a name with a fixed head or tail.
type nameLookup struct {
	kind    segmentKind
	literal string
}

// enumerateLookups returns index lookups covering every name this segment can match, or nil when it
// cannot be reduced to a finite set.
//
// A segment whose only metacharacters are alternations and classes denotes a finite set: `{go,go.exe}`
// is two names, `*.[jw]ar` two suffixes, `[lm]*` two prefixes - a few lookups rather than a scan.
// Bounds serve these poorly: `*.[jw]ar` bounds to suffix "ar" (catches `calendar`), `[lm]*` bounds to
// nothing.
//
// Over-broad enumeration only costs filtering; under-broad loses files, so anything not exactly
// enumerable - a negated class, a POSIX class, a metacharacter member - abandons the attempt.
func enumerateLookups(segment string) []nameLookup {
	alternatives, ok := expandBraces(segment)
	if !ok {
		return nil
	}

	var expanded []string
	for _, alternative := range alternatives {
		members, ok := expandClasses(alternative)
		if !ok || len(expanded)+len(members) > maxAlternatives {
			return nil
		}
		expanded = append(expanded, members...)
	}

	lookups := make([]nameLookup, 0, len(expanded))
	seen := make(map[nameLookup]struct{}, len(expanded))
	for _, alternative := range dedupe(expanded) {
		lookup, ok := lookupFor(alternative)
		if !ok {
			// one alternative without a lookup would leave its matches out
			return nil
		}
		if _, dup := seen[lookup]; dup {
			continue
		}
		seen[lookup] = struct{}{}
		lookups = append(lookups, lookup)
	}
	return lookups
}

// lookupFor classifies one fully-expanded alternative (no alternation, no class) as an index lookup,
// or reports false when the index cannot answer it usefully. The answerable shapes are an exact name,
// `*tail`, `head*`; a `?`, an escape, or a second `*` leaves text the index cannot key on.
func lookupFor(alternative string) (nameLookup, bool) {
	if strings.ContainsAny(alternative, nonWildcardMeta) {
		return nameLookup{}, false
	}
	first := strings.IndexByte(alternative, '*')
	last := strings.LastIndexByte(alternative, '*')
	switch {
	case first < 0:
		return nameLookup{kind: segExact, literal: alternative}, true
	case first != last || len(alternative) == 1:
		// `*a*` needs every name anyway, and a bare `*` takes them all
		return nameLookup{}, false
	case first == 0:
		return worthLooking(nameLookup{kind: segSuffix, literal: alternative[1:]})
	case last == len(alternative)-1:
		return worthLooking(nameLookup{kind: segPrefix, literal: alternative[:len(alternative)-1]})
	}
	// `head*tail`, which neither index answers on its own
	return nameLookup{}, false
}

func worthLooking(lookup nameLookup) (nameLookup, bool) {
	if len(lookup.literal) < minLiteralBound {
		return nameLookup{}, false
	}
	return lookup, true
}

// expandClasses enumerates the names a segment's `[...]` classes stand for, reporting false when a
// class cannot be enumerated exactly.
//
// Members are substituted back as themselves, so a metacharacter member would change the pattern's
// meaning (`[*]` matches one asterisk, not anything). Such a class is refused rather than escaped,
// since the caller's fallback is correct.
func expandClasses(segment string) ([]string, bool) {
	open := firstClass(segment)
	if open < 0 {
		return []string{segment}, true
	}
	closing := classEnd(segment, open)
	if closing < 0 {
		// unterminated, so doublestar reads the `[` as literal; lookupFor will refuse it
		return []string{segment}, true
	}

	members, ok := classMembers(segment[open : closing+1])
	if !ok {
		return nil, false
	}

	var out []string
	for _, member := range members {
		expanded, ok := expandClasses(segment[:open] + member + segment[closing+1:])
		if !ok || len(out)+len(expanded) > maxAlternatives {
			return nil, false
		}
		out = append(out, expanded...)
	}
	return out, true
}

// firstClass returns the index of the first unescaped `[`, or -1.
func firstClass(segment string) int {
	for i := 0; i < len(segment); i++ {
		switch segment[i] {
		case '\\':
			i++
		case '[':
			return i
		}
	}
	return -1
}

// classMembers returns the characters the given `[...]` matches, or false when the class is not
// enumerable.
func classMembers(class string) ([]string, bool) {
	runes := []rune(class[1 : len(class)-1])
	if !enumerableClass(runes) {
		return nil, false
	}

	var out []string
	for i := 0; i < len(runes); i++ {
		members, width, ok := classItemAt(runes, i)
		if !ok {
			return nil, false
		}
		out = append(out, members...)
		if len(out) > maxAlternatives {
			return nil, false
		}
		i += width
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// enumerableClass reports whether the inside of a `[...]` describes a listable finite set. A negated
// class stands for all but a few characters, and a POSIX class for a set this does not model.
func enumerableClass(inner []rune) bool {
	switch {
	case len(inner) == 0:
		return false
	case inner[0] == '!' || inner[0] == '^':
		return false
	case strings.Contains(string(inner), "[:"):
		return false
	}
	return true
}

// classItemAt returns the members of the class item starting at i and how many runes past i it
// consumed. An item is an escape, an `a-z` range, or a single character.
func classItemAt(runes []rune, i int) (members []string, width int, ok bool) {
	switch {
	case runes[i] == '\\':
		if i+1 >= len(runes) || !enumerableMember(runes[i+1]) {
			return nil, 0, false
		}
		return []string{string(runes[i+1])}, 1, true

	case i+2 < len(runes) && runes[i+1] == '-':
		return classRange(runes[i], runes[i+2])

	default:
		if !enumerableMember(runes[i]) {
			return nil, 0, false
		}
		return []string{string(runes[i])}, 0, true
	}
}

// classRange expands an `a-z` range into its members, refusing one wider than maxClassRange.
func classRange(low, high rune) (members []string, width int, ok bool) {
	if high < low || high-low > maxClassRange {
		return nil, 0, false
	}
	for r := low; r <= high; r++ {
		if !enumerableMember(r) {
			return nil, 0, false
		}
		members = append(members, string(r))
	}
	return members, 2, true
}

// enumerableMember reports whether a class member can stand in the pattern as itself, which a
// metacharacter cannot: see expandClasses.
func enumerableMember(r rune) bool {
	return !strings.ContainsRune(globMeta, r)
}
