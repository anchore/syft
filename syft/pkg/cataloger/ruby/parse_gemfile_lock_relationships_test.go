package ruby

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_isGemSpecLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"spec entry (4-space indent)", "    rake (13.0.6)", true},
		{"dependency entry (6-space indent)", "      actionpack (= 6.1.4)", false},
		{"section header", "GEM", false},
		{"too short", "  x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isGemSpecLine(tt.line))
		})
	}
}

func Test_isGemDependencyLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"dependency entry (6-space indent)", "      actionpack (= 6.1.4)", true},
		{"dependency without constraint", "      coffee-rails", true},
		{"spec entry (4-space indent)", "    rake (13.0.6)", false},
		{"too short", "    x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isGemDependencyLine(tt.line))
		})
	}
}

func Test_isDirectDependencyLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"declared gem with constraint (2-space indent)", "  rails (= 4.1.1)", true},
		{"declared gem from a git source", "  turbolinks!", true},
		{"spec entry (4-space indent)", "    rake (13.0.6)", false},
		{"section header", "DEPENDENCIES", false},
		{"too short", " x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDirectDependencyLine(tt.line))
		})
	}
}

func Test_gemfileLockDependencySpecifier(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "provides its name and requires its dependencies",
			p: pkg.Package{
				Name: "cowboy",
				Metadata: pkg.RubyGemfileLockEntry{
					Name:         "cowboy",
					Dependencies: []string{"cowlib", "ranch"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"cowboy"},
					Requires: []string{"cowlib", "ranch"},
				},
			},
		},
		{
			name: "no dependencies still provides its name",
			p: pkg.Package{
				Name: "rake",
				Metadata: pkg.RubyGemfileLockEntry{
					Name: "rake",
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"rake"},
				},
			},
		},
		{
			name: "wrong metadata type yields empty specification",
			p: pkg.Package{
				Name:     "mystery",
				Metadata: pkg.RubyGemspec{},
			},
			want: dependency.Specification{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, gemfileLockDependencySpecifier(tt.p))
		})
	}
}

func TestCataloger_Relationships(t *testing.T) {
	// cowboy requires cowlib and ranch (both locked); the dependency.Processor
	// wired into the cataloger turns those into dependency-of relationships.
	expectedRelationships := []string{
		"cowlib @ 2.11.0 (Gemfile.lock) [dependency-of] cowboy @ 2.9.0 (Gemfile.lock)",
		"ranch @ 1.8.0 (Gemfile.lock) [dependency-of] cowboy @ 2.9.0 (Gemfile.lock)",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/relationships").
		ExpectsRelationshipStrings(expectedRelationships).
		TestCataloger(t, NewGemFileLockCataloger())
}

func TestCataloger_RelationshipsStayWithinEachLockfile(t *testing.T) {
	// two apps in one scan lock different versions of rack; each app's gem must
	// only depend on the rack locked next to it.
	expectedRelationships := []string{
		"rack @ 2.2.8 (app-a/Gemfile.lock) [dependency-of] rails @ 7.1.3 (app-a/Gemfile.lock)",
		"rack @ 3.0.9 (app-b/Gemfile.lock) [dependency-of] sinatra @ 4.0.0 (app-b/Gemfile.lock)",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/multiple-lockfiles").
		ExpectsRelationshipStrings(expectedRelationships).
		TestCataloger(t, NewGemFileLockCataloger())
}

func TestCataloger_DirectDependencies(t *testing.T) {
	// cowboy is listed under DEPENDENCIES; cowlib and ranch are only required by
	// it. Direct must survive the full cataloger, not just the parser.
	want := map[string]bool{"cowboy": true, "cowlib": false, "ranch": false}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/relationships").
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			got := map[string]bool{}
			for _, p := range pkgs {
				metadata, ok := p.Metadata.(pkg.RubyGemfileLockEntry)
				require.True(t, ok, "%s has metadata %T", p.Name, p.Metadata)
				got[p.Name] = metadata.Direct
			}
			assert.Equal(t, want, got)
		}).
		TestCataloger(t, NewGemFileLockCataloger())
}
