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
		include    []string
		modulePath string
		want       bool
	}{
		{
			name:       "none selects nothing",
			scope:      cataloging.SymbolScopeNone,
			modulePath: "github.com/foo/bar",
		},
		{
			name:       "none is inert even with includes",
			scope:      cataloging.SymbolScopeNone,
			include:    []string{"github.com/foo/**"},
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
			// a single star does not cross "/", which is why doublestar is needed: go module paths carry
			// /v2-style major version suffixes that must not be swept up by a single-segment pattern
			name:       "single star matches one path segment",
			scope:      cataloging.SymbolScopeStdlib,
			include:    []string{"github.com/klauspost/*"},
			modulePath: "github.com/klauspost/compress",
			want:       true,
		},
		{
			name:       "single star does not cross a separator",
			scope:      cataloging.SymbolScopeStdlib,
			include:    []string{"github.com/klauspost/*"},
			modulePath: "github.com/klauspost/compress/v2",
		},
		{
			name:       "doublestar crosses a separator",
			scope:      cataloging.SymbolScopeStdlib,
			include:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/klauspost/compress/v2",
			want:       true,
		},
		{
			name:       "includes widen a preset",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			include:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/klauspost/compress",
			want:       true,
		},
		{
			name:       "includes cannot narrow a preset",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			include:    []string{"github.com/klauspost/**"},
			modulePath: "golang.org/x/net",
			want:       true,
		},
		{
			name:       "exact module path",
			scope:      cataloging.SymbolScopeStdlib,
			include:    []string{"google.golang.org/grpc"},
			modulePath: "google.golang.org/grpc",
			want:       true,
		},
		{
			name:       "empty includes are a no-op",
			scope:      cataloging.SymbolScopeStdlib,
			include:    []string{},
			modulePath: "github.com/foo/bar",
		},
		{
			// all short-circuits before any matching, so an include list cannot subtract from it
			name:       "includes cannot narrow all",
			scope:      cataloging.SymbolScopeAll,
			include:    []string{"github.com/klauspost/**"},
			modulePath: "github.com/foo/bar",
			want:       true,
		},
		{
			// selection is a per-module boolean, so a pattern overlapping the preset is idempotent
			name:       "include overlapping the preset is idempotent",
			scope:      cataloging.SymbolScopeExtendedStdlib,
			include:    []string{"golang.org/x/**"},
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
			include:    []string{"github.com/foo/**"},
			modulePath: "github.com/foo/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newSymbolSelector(tt.scope, tt.include).selects(tt.modulePath))
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
		include []string
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
			name:    "includes widen the selection",
			scope:   cataloging.SymbolScopeExtendedStdlib,
			include: []string{"github.com/klauspost/**"},
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
			got := newSymbolSelector(tt.scope, tt.include).filter(symbols())
			if len(tt.want) == 0 {
				// nil, not an empty map, so the omitempty JSON tag keeps the field out of output
				assert.Nil(t, got)
				return
			}
			assert.ElementsMatch(t, tt.want, slices.Collect(maps.Keys(got)))
		})
	}
}
