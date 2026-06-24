package ruby

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
