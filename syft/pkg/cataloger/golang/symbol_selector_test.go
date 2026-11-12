package golang

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging"
)

func Test_symbolSelector_selects(t *testing.T) {
	tests := []struct {
		name       string
		scope      cataloging.SymbolScope
		modules    []string
		modulePath string
		want       bool
	}{
		{
			name:       "none selects nothing",
			scope:      cataloging.SymbolScopeNone,
			modulePath: "github.com/foo/bar",
		},
		{
			name:       "none is inert even with module patterns",
			scope:      cataloging.SymbolScopeNone,
			modules:    []string{"github.com/foo/**"},
			modulePath: "github.com/foo/bar",
		},
		{
			name:       "all selects everything",
			scope:      cataloging.SymbolScopeAll,
			modulePath: "github.com/foo/bar",
			want:       true,
		},
		{
			name:       "stdlib selects no modules",
			scope:      cataloging.SymbolScopeStdlib,
			modulePath: "golang.org/x/crypto",
		},
		{
			name:       "extended-stdlib matches a golang.org/x module",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modulePath: "golang.org/x/crypto",
			want:       true,
		},
		{
			// ** crosses path separators, which is what lets one pattern cover the whole subtree
			name:       "extended-stdlib matches a nested golang.org/x module",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modulePath: "golang.org/x/tools/gopls",
			want:       true,
		},
		{
			// the pattern must not match on a bare prefix, only at a path boundary
			name:       "extended-stdlib does not match golang.org/xtra",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modulePath: "golang.org/xtra",
		},
		{
			name:       "extended-stdlib does not match an unrelated module",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modulePath: "github.com/klauspost/compress",
		},
		{
			name:       "single star matches one path segment",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/*"},
			modulePath: "github.com/klauspost/compress",
			want:       true,
		},
		{
			// a single star does not cross "/", but a major version suffix is not a path segment for this
			// purpose: the module is matched with the suffix stripped as well, so a config written before a
			// major bump keeps covering the module after it
			name:       "single star reaches across a major version suffix",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/*"},
			modulePath: "github.com/klauspost/compress/v2",
			want:       true,
		},
		{
			name:       "single star does not cross a separator that is not a version suffix",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/*"},
			modulePath: "github.com/klauspost/compress/internal/thing",
		},
		{
			// only a trailing suffix is a version. here "v2" is an ordinary path element naming the major
			// subdirectory a nested module lives in, so it is matched literally and ** is the way to reach it
			name:       "a mid-path version-like element is an ordinary segment",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/anchore/*/thing"},
			modulePath: "github.com/anchore/syft/v2/thing",
		},
		{
			name:       "doublestar reaches a mid-path version-like element",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/anchore/**/thing"},
			modulePath: "github.com/anchore/syft/v2/thing",
			want:       true,
		},
		{
			name:       "doublestar crosses a separator",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/klauspost/compress/v2",
			want:       true,
		},
		{
			name:       "an exact path covers every major version of that module",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/compress"},
			modulePath: "github.com/klauspost/compress/v2",
			want:       true,
		},
		{
			// spelling the suffix out is how a single major version is targeted: v1's path carries no suffix,
			// so there is nothing for a suffixed pattern to match
			name:       "a pattern naming a major version selects only that one",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/compress/v2"},
			modulePath: "github.com/klauspost/compress",
		},
		{
			name:       "a pattern naming a major version selects it",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/compress/v2"},
			modulePath: "github.com/klauspost/compress/v2",
			want:       true,
		},
		{
			// gopkg.in spells the major version as a .vN suffix on the last element, which SplitPathVersion
			// understands, so it strips the same way
			name:       "gopkg.in style suffixes strip too",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"gopkg.in/yaml"},
			modulePath: "gopkg.in/yaml.v2",
			want:       true,
		},
		{
			// /v1 and /v0 are not valid major version suffixes, so this is not a versioned path at all and
			// nothing is stripped from it
			name:       "a v1 element is not a version suffix",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"github.com/klauspost/compress"},
			modulePath: "github.com/klauspost/compress/v1",
		},
		{
			name:       "module patterns widen a preset",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modules:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/klauspost/compress",
			want:       true,
		},
		{
			name:       "module patterns cannot narrow a preset",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modules:    []string{"github.com/klauspost/**"},
			modulePath: "golang.org/x/net",
			want:       true,
		},
		{
			name:       "exact module path",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{"google.golang.org/grpc"},
			modulePath: "google.golang.org/grpc",
			want:       true,
		},
		{
			name:       "an empty module pattern list is a no-op",
			scope:      cataloging.SymbolScopeStdlib,
			modules:    []string{},
			modulePath: "github.com/foo/bar",
		},
		{
			// all short-circuits before any matching, so a module pattern list cannot subtract from it
			name:       "module patterns cannot narrow all",
			scope:      cataloging.SymbolScopeAll,
			modules:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/foo/bar",
			want:       true,
		},
		{
			// selection is a per-module boolean, so a pattern overlapping the preset is idempotent
			name:       "a module pattern overlapping the preset is idempotent",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			modules:    []string{"golang.org/x/**"},
			modulePath: "golang.org/x/net",
			want:       true,
		},
		{
			// library consumers set CaptureSymbols directly without going through PostLoad, so the
			// selector normalizes rather than falling through to stdlib-only capture
			name:       "unnormalized scope is parsed",
			scope:      "All",
			modulePath: "github.com/foo/bar",
			want:       true,
		},
		{
			name:       "unrecognized scope resolves to none",
			scope:      "bogus",
			modules:    []string{"github.com/foo/**"},
			modulePath: "github.com/foo/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newSymbolSelector(tt.scope, tt.modules).selects(tt.modulePath))
		})
	}
}

// a malformed pattern must be dropped at construction, leaving the remaining patterns in force rather
// than aborting the selection or silently matching nothing
func Test_symbolSelector_malformedPattern(t *testing.T) {
	s := newSymbolSelector(cataloging.SymbolScopeExtendedStdlib, []string{"[", "github.com/klauspost/**"})

	require.Equal(t, []string{"golang.org/x/**", "github.com/klauspost/**"}, s.patterns)
	assert.True(t, s.selects("golang.org/x/net"), "preset still applies")
	assert.True(t, s.selects("github.com/klauspost/compress"), "valid sibling pattern still applies")
	assert.False(t, s.selects("github.com/foo"), "malformed pattern selects nothing")
}

func Test_symbolSelector_filter(t *testing.T) {
	symbols := func() map[string]map[string][]string {
		return map[string]map[string][]string{
			"golang.org/x/net":              {"golang.org/x/net/http2": {"NewClientConn"}},
			"github.com/klauspost/compress": {"github.com/klauspost/compress/zstd": {"NewReader"}},
		}
	}

	tests := []struct {
		name    string
		scope   cataloging.SymbolScope
		modules []string
		want    []string // remaining module paths
	}{
		{
			name:  "none drops everything",
			scope: cataloging.SymbolScopeNone,
		},
		{
			name:  "stdlib drops every module",
			scope: cataloging.SymbolScopeStdlib,
		},
		{
			name:  "extended-stdlib keeps only golang.org/x",
			scope: cataloging.SymbolScopeExtendedStdlib,
			want:  []string{"golang.org/x/net"},
		},
		{
			name:    "module patterns widen the selection",
			scope:   cataloging.SymbolScopeExtendedStdlib,
			modules: []string{"github.com/klauspost/**"},
			want:    []string{"golang.org/x/net", "github.com/klauspost/compress"},
		},
		{
			name:  "all keeps everything",
			scope: cataloging.SymbolScopeAll,
			want:  []string{"golang.org/x/net", "github.com/klauspost/compress"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newSymbolSelector(tt.scope, tt.modules).filter(symbols())
			if len(tt.want) == 0 {
				// nil, not an empty map, so the omitempty JSON tag keeps the field out of output
				assert.Nil(t, got)
				return
			}
			assert.ElementsMatch(t, tt.want, slices.Collect(maps.Keys(got)))
		})
	}
}
