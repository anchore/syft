package fileresolver

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftindex "github.com/anchore/syft/internal/index"
)

func Test_literalBounds(t *testing.T) {
	tests := []struct {
		segment string
		prefix  string
		suffix  string
	}{
		{"pom.properties", "pom.properties", "pom.properties"},
		{"libstd-????????????????.so", "libstd-", ".so"},
		{"*.[jw]ar", "", "ar"},
		{"*.jar", "", ".jar"},
		{"pom*", "pom", ""},
		{"*", "", ""},
		{"{go,go.exe}", "", ""},
		{"lib{a,b}.so", "lib", ".so"},
		{"a?b", "a", "b"},
		{`esc\*ape`, "esc", "ape"},
	}
	for _, tt := range tests {
		t.Run(tt.segment, func(t *testing.T) {
			prefix, suffix := literalBounds(tt.segment)
			assert.Equal(t, tt.prefix, prefix, "prefix")
			assert.Equal(t, tt.suffix, suffix, "suffix")
		})
	}
}

func Test_expandBraces(t *testing.T) {
	tests := []struct {
		segment string
		want    []string
		wantOK  bool
	}{
		{segment: "plain.txt", want: []string{"plain.txt"}, wantOK: true},
		{segment: "{go,go.exe}", want: []string{"go", "go.exe"}, wantOK: true},
		{segment: "lib{a,b}.so", want: []string{"liba.so", "libb.so"}, wantOK: true},
		{segment: "{a,{b,c}}x", want: []string{"ax", "bx", "cx"}, wantOK: true},
		{segment: "{a,b}{c,d}", want: []string{"ac", "ad", "bc", "bd"}, wantOK: true},
		// a comma inside a character class is not a separator
		{segment: "{x[a,b]y,z}", want: []string{"x[a,b]y", "z"}, wantOK: true},
		// an escaped brace is not a group
		{segment: `\{a,b\}`, want: []string{`\{a,b\}`}, wantOK: true},
		// unmatched, so left alone for literalBounds to stop at
		{segment: "{unclosed", want: []string{"{unclosed"}, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.segment, func(t *testing.T) {
			got, ok := expandBraces(tt.segment)
			require.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("an exponential expansion is refused rather than enumerated", func(t *testing.T) {
		_, ok := expandBraces(strings.Repeat("{a,b}", 10))
		assert.False(t, ok, "2^10 alternatives is not less work than a scan")
	})
}

func Test_segmentBounds(t *testing.T) {
	tests := []struct {
		name         string
		segment      string
		wantPrefixes []string
		wantSuffixes []string
	}{
		{
			name:         "both sides fixed",
			segment:      "libstd-????????????????.so",
			wantPrefixes: []string{"libstd-"},
			wantSuffixes: []string{".so"},
		},
		{
			name:         "only the tail is fixed",
			segment:      "*.[jw]ar",
			wantSuffixes: []string{"ar"},
		},
		{
			name:         "only the head is fixed",
			segment:      "pom?.xml*",
			wantPrefixes: []string{"pom"},
		},
		{
			name:         "alternation fixes each branch",
			segment:      "{go,go.exe}",
			wantPrefixes: []string{"go", "go.exe"},
			wantSuffixes: []string{"go", "go.exe"},
		},
		{
			name:         "alternation around fixed text",
			segment:      "{mariadb,mysql}",
			wantPrefixes: []string{"mariadb", "mysql"},
			wantSuffixes: []string{"mariadb", "mysql"},
		},
		{
			name:    "a branch with nothing fixed disqualifies the whole side",
			segment: "{go,*}",
		},
		{
			name:         "a one-character bound is still a lookup",
			segment:      "a?",
			wantPrefixes: []string{"a"},
		},
		{
			name:    "nothing fixed at all",
			segment: "*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes, suffixes := segmentBounds(tt.segment)
			assert.Equal(t, tt.wantPrefixes, prefixes, "prefixes")
			assert.Equal(t, tt.wantSuffixes, suffixes, "suffixes")
		})
	}
}

// Test_segmentBounds_neverExcludesAMatch is the invariant the optimization rests on: the bounds pick
// which names doublestar is shown, so a name the pattern matches must carry one. A bound that is too
// short only widens the candidate set; one that is too long silently loses files.
func Test_segmentBounds_neverExcludesAMatch(t *testing.T) {
	segments := []string{
		"libstd-????????????????.so", "*.[jw]ar", "{go,go.exe}", "{mariadb,mysql}",
		"lib{a,b}.so", "pom?.xml", "*.jar", "pom*", "*", "a?b", "{a,{b,c}}x",
		`esc\*ape`, "[!x]yz", "{firefox,firefox.exe}", "**",
	}
	names := []string{
		"go", "go.exe", "gopher", "a.jar", "b.war", "b.rar", "libstd-0123456789abcdef.so",
		"libstd-short.so", "liba.so", "libb.so", "libc.so", "pom1.xml", "pom.xml", "pom",
		"mariadb", "mysql", "postgres", "axb", "ax", "bx", "cx", "esc*ape", "escape",
		"xyz", "ayz", "firefox", "firefox.exe", "", "{go,go.exe}",
	}

	for _, segment := range segments {
		t.Run(segment, func(t *testing.T) {
			prefixes, suffixes := segmentBounds(segment)
			for _, name := range names {
				matched, err := doublestar.Match(segment, name)
				if err != nil || !matched {
					continue
				}
				if len(prefixes) > 0 {
					assert.True(t, anyHasPrefix(name, prefixes),
						"%q matches %q but carries none of the prefixes %q", name, segment, prefixes)
				}
				if len(suffixes) > 0 {
					assert.True(t, anyHasSuffix(name, suffixes),
						"%q matches %q but carries none of the suffixes %q", name, segment, suffixes)
				}
			}
		})
	}
}

func anyHasPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func anyHasSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func Test_classMembers(t *testing.T) {
	tests := []struct {
		class  string
		want   []string
		wantOK bool
	}{
		{class: "[jw]", want: []string{"j", "w"}, wantOK: true},
		{class: "[a-c]", want: []string{"a", "b", "c"}, wantOK: true},
		{class: "[a-cx]", want: []string{"a", "b", "c", "x"}, wantOK: true},
		{class: "[-a]", want: []string{"-", "a"}, wantOK: true},
		{class: "[a-]", want: []string{"a", "-"}, wantOK: true},
		// a negated class stands for every character but a few, which is not a finite lookup
		{class: "[!x]"},
		{class: "[^x]"},
		// a POSIX class is a set this does not model
		{class: "[[:alpha:]]"},
		// a member that is itself a metacharacter would change meaning on substitution
		{class: "[*]"},
		{class: "[?]"},
		// wider than maxClassRange
		{class: "[\x20-\x7e]"},
		{class: "[]"},
	}
	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			got, ok := classMembers(tt.class)
			require.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_enumerateLookups(t *testing.T) {
	tests := []struct {
		name    string
		segment string
		want    []nameLookup
	}{
		{
			name:    "alternation of exact names",
			segment: "{go,go.exe}",
			want:    []nameLookup{{segExact, "go"}, {segExact, "go.exe"}},
		},
		{
			name:    "class inside an extension becomes exact suffixes",
			segment: "*.[jw]ar",
			want:    []nameLookup{{segSuffix, ".jar"}, {segSuffix, ".war"}},
		},
		{
			name:    "leading class becomes prefix lookups, where bounds fix nothing at all",
			segment: "[lm]*",
			want:    []nameLookup{{segPrefix, "l"}, {segPrefix, "m"}},
		},
		{
			name:    "multi-character alternation likewise",
			segment: "{lib,mod}*",
			want:    []nameLookup{{segPrefix, "lib"}, {segPrefix, "mod"}},
		},
		{
			name:    "alternation and class together",
			segment: "{lib,bin}[0-2].so",
			want: []nameLookup{
				{segExact, "lib0.so"}, {segExact, "lib1.so"}, {segExact, "lib2.so"},
				{segExact, "bin0.so"}, {segExact, "bin1.so"}, {segExact, "bin2.so"},
			},
		},
		{
			name:    "duplicate alternatives collapse to one lookup",
			segment: "{go,go}",
			want:    []nameLookup{{segExact, "go"}},
		},
		// a `?` is not a finite set of names
		{name: "question mark", segment: "libstd-?.so"},
		// a negated class is not either
		{name: "negated class", segment: "[!x]yz"},
		// nor is a wildcard in the middle
		{name: "interior wildcard", segment: "{a,b}*.{c,d}"},
		// nor a bare wildcard
		{name: "bare wildcard", segment: "{a,*}"},
		// and an exponential expansion is refused rather than enumerated
		{name: "too many alternatives", segment: "[a-z][a-z]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, enumerateLookups(tt.segment))
		})
	}
}

// Test_enumerateLookups_neverExcludesAMatch is the same invariant for the stronger claim this pass
// makes: the lookups are what the index is asked for, so a name the pattern matches must be found by
// at least one of them. Over-broad only costs filtering.
func Test_enumerateLookups_neverExcludesAMatch(t *testing.T) {
	segments := []string{
		"{go,go.exe}", "*.[jw]ar", "[lm]*", "{lib,mod}*", "{mariadb,mysql}", "{lib,bin}[0-2].so",
		"lib{a,b}.so", "[abc]", "*.[jw]ar", "{firefox,firefox.exe}", "x[!y]z", "[a-c]*.so",
		"pom.{xml,properties}", "*.{jar,war}", "{a,b}{c,d}",
		// only some branches reduce to a lookup
		"{go,*}", "{lib,l}*", "{lo,m}*", "{*.jar,pom.xml}",
	}
	names := []string{
		"go", "go.exe", "gopher", "a.jar", "b.war", "c.rar", "calendar", "lib0.so", "lib1.so",
		"lib3.so", "bin2.so", "liba.so", "libb.so", "libc.so", "mariadb", "mysql", "a", "b", "c", "d",
		"lmn", "mno", "nop", "xyz", "xaz", "ayz", "firefox", "firefox.exe", "pom.xml",
		"log.txt", "mn.txt", "lib.so",
		"pom.properties", "pom.txt", "ac", "ad", "bc", "bd", "ab", "", "az.so",
	}

	for _, segment := range segments {
		t.Run(segment, func(t *testing.T) {
			lookups := enumerateLookups(segment)
			if len(lookups) == 0 {
				return
			}
			for _, name := range names {
				matched, err := doublestar.Match(segment, name)
				if err != nil || !matched {
					continue
				}
				assert.True(t, anyLookupFinds(name, lookups),
					"%q matches %q but no lookup in %v would find it", name, segment, lookups)
			}
		})
	}
}

func anyLookupFinds(name string, lookups []nameLookup) bool {
	for _, l := range lookups {
		switch l.kind {
		case segExact:
			if name == l.literal {
				return true
			}
		case segPrefix:
			if strings.HasPrefix(name, l.literal) {
				return true
			}
		case segSuffix:
			if strings.HasSuffix(name, l.literal) {
				return true
			}
		}
	}
	return false
}

// Test_lookupsAreExactlyTheirAlternative is what lets byLookups return the index's answer without
// asking doublestar to confirm it.
//
// The bounds path only narrows, so an imprecise bound there costs filtering. A lookup is the answer
// itself, so anything byPrefix("l") selected that `l*` does not match would be reported as a match.
// This pins the three shapes to doublestar's verdict.
func Test_lookupsAreExactlyTheirAlternative(t *testing.T) {
	alternatives := []string{
		"go", "go.exe", "l", "lib", "*.jar", "*ar", "*", "l*", "lib*", "libstd-*",
		"*.so", "a", "pom.xml", ".hidden", "*.", ".*",
	}
	names := []string{
		"go", "go.exe", "gopher", "l", "lib", "lib.so", "libstd-0.a", "libz.so", "a.jar",
		"calendar", "ar", ".jar", "", "a", "pom.xml", ".hidden", "x.", ".x", "日本.jar", "日本",
	}

	for _, alternative := range alternatives {
		t.Run(alternative, func(t *testing.T) {
			lookup, ok := lookupFor(alternative)
			if !ok {
				return
			}
			for _, name := range names {
				want, err := doublestar.Match(alternative, name)
				require.NoError(t, err)
				assert.Equal(t, want, anyLookupFinds(name, []nameLookup{lookup}),
					"pattern %q, name %q: the lookup and doublestar must agree exactly", alternative, name)
			}
		})
	}
}

// Test_boundedLookupMatchesTheFullOne holds the probe to the lookup it stands in for: a bounded
// lookup that completes has to return exactly what the unbounded one would, or the side it picks is
// answering a different question than the side it rejects.
func Test_boundedLookupMatchesTheFullOne(t *testing.T) {
	var x syftindex.PrefixSuffix[[]*indexNode]
	names := []string{
		"libstd-a.so", "libstd-b.a", "libstd-c.a", "lib.so", "libz.so",
		"go", "go.exe", "gopher", "a.jar", "b.war", "\xff\xfe",
	}
	for _, name := range names {
		node := &indexNode{name: name}
		x.Update(name, appendNode(node))
	}

	for _, probe := range []string{"lib", "libstd-", "go", "z", "", "a", "\xff", "libstd-a.so"} {
		t.Run("prefix "+probe, func(t *testing.T) {
			full := flattenNodes(x.ByPrefix(probe))
			got, complete := x.ByPrefixUpTo(probe, len(names))
			require.True(t, complete, "the budget covers every name, so nothing may give up")
			assert.ElementsMatch(t, full, flattenNodes(got))
		})
		t.Run("suffix "+probe, func(t *testing.T) {
			full := flattenNodes(x.BySuffix(probe))
			got, complete := x.BySuffixUpTo(probe, len(names))
			require.True(t, complete)
			assert.ElementsMatch(t, full, flattenNodes(got))
		})
	}
}

// Test_boundedLookupGivesUpPastTheBudget covers the other half: past the budget the lookup must report
// failure rather than a short answer, which a caller would read as a narrow side.
func Test_boundedLookupGivesUpPastTheBudget(t *testing.T) {
	var x syftindex.PrefixSuffix[[]*indexNode]
	for i := range 100 {
		name := fmt.Sprintf("lib%03d.so", i)
		x.Update(name, appendNode(&indexNode{name: name}))
	}

	_, complete := x.ByPrefixUpTo("lib", 10)
	assert.False(t, complete, "100 names under a budget of 10 must give up")

	_, complete = x.ByPrefixUpTo("lib000", 10)
	assert.True(t, complete, "one name under a budget of 10 must not")
}

// Test_narrowByBounds_takesTheNarrowerSide covers what probing the index buys. Both ends of
// `libstd-????????????????.so` can answer it, and which should is a property of the archive: here the
// seven-character head is the broad side and the three-character tail the narrow one, so a rule
// preferring the longer literal would take the worse lookup.
func Test_narrowByBounds_takesTheNarrowerSide(t *testing.T) {
	entries := map[string]string{"usr/lib/libstd-0123456789abcdef.so": "real"}
	for i := range 200 {
		entries[fmt.Sprintf("usr/lib/libstd-%04d.a", i)] = "decoy"
	}
	r := indexOver(t, 1<<20, entries)

	const segment = "libstd-????????????????.so"
	prefixes, suffixes := segmentBounds(segment)
	require.Equal(t, []string{"libstd-"}, prefixes)
	require.Equal(t, []string{".so"}, suffixes)

	// the head reaches every decoy and so must never be the side that runs; the tail reaches one
	_, headComplete := r.fileNames.ByPrefixUpTo("libstd-", boundProbe)
	require.False(t, headComplete, "the longer bound reaches past the probe")
	tail, tailComplete := r.fileNames.BySuffixUpTo(".so", boundProbe)
	require.True(t, tailComplete)
	require.Len(t, flattenNodes(tail), 1, "the shorter bound reaches only the real file")

	candidates, ok := r.narrowByBounds(&r.fileNames, segment)
	require.True(t, ok)
	assert.Len(t, candidates, 1, "the narrower side must be the one that ran")

	// and the answer is the same either way, so this is only a question of cost
	locations, err := r.FilesByGlob("**/" + segment)
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "usr/lib/libstd-0123456789abcdef.so", locations[0].RealPath)
}

// Test_narrowByBounds_fallsBackWhenNeitherSideIsNarrow covers the case the probe cannot decide: both
// ends reach past it, so the answer still has to be complete.
func Test_narrowByBounds_fallsBackWhenNeitherSideIsNarrow(t *testing.T) {
	entries := map[string]string{}
	for i := range boundProbe * 3 {
		entries[fmt.Sprintf("usr/lib/libstd-%04d.so", i)] = "decoy"
	}
	entries["usr/lib/libstd-0123456789abcdef.so"] = "real"
	r := indexOver(t, 1<<20, entries)

	candidates, ok := r.narrowByBounds(&r.fileNames, "libstd-????????????????.so")
	require.True(t, ok)
	assert.Len(t, candidates, boundProbe*3+1, "a probe that decides nothing must still gather everything")

	locations, err := r.FilesByGlob("**/libstd-????????????????.so")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "usr/lib/libstd-0123456789abcdef.so", locations[0].RealPath)
}
