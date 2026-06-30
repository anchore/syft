package ruby

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGemspec(t *testing.T) {
	fixture := "testdata/bundler.gemspec"
	ctx := context.TODO()
	locations := file.NewLocationSet(file.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:      "bundler",
		Version:   "2.1.4",
		PURL:      "pkg:gem/bundler@2.1.4",
		Locations: locations,
		Type:      pkg.GemPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation(fixture)),
		),
		Language: pkg.Ruby,
		Metadata: pkg.RubyGemspec{
			Name:     "bundler",
			Version:  "2.1.4",
			Files:    []string{"exe/bundle", "exe/bundler"},
			Authors:  []string{"André Arko", "Samuel Giddins", "Colby Swandale", "Hiroshi Shibata", "David Rodríguez", "Grey Baker", "Stephanie Morillo", "Chris Morris", "James Wen", "Tim Moore", "André Medeiros", "Jessica Lynn Suttles", "Terence Lee", "Carl Lerche", "Yehuda Katz"},
			Homepage: "https://bundler.io",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseGemSpecEntries, []pkg.Package{expectedPkg}, nil)
}

func TestResolveRubyInterpolationsInFields(t *testing.T) {
	tests := []struct {
		name         string
		fields       map[string]any
		wantHomepage string // "" with wantDropped=true means the key should be absent
		wantDropped  bool
	}{
		{
			name:         "resolves #{s.name}",
			fields:       map[string]any{"name": "formatador", "homepage": "https://github.com/geemus/#{s.name}"},
			wantHomepage: "https://github.com/geemus/formatador",
		},
		{
			name:         "resolves #{s.version}",
			fields:       map[string]any{"version": "1.1.0", "homepage": "https://example.com/v/#{s.version}"},
			wantHomepage: "https://example.com/v/1.1.0",
		},
		{
			name:         "resolves #{gem.name}",
			fields:       map[string]any{"name": "foo", "homepage": "https://x/#{gem.name}"},
			wantHomepage: "https://x/foo",
		},
		{
			name:         "resolves #{spec.version}",
			fields:       map[string]any{"version": "2.0", "homepage": "https://x/#{spec.version}"},
			wantHomepage: "https://x/2.0",
		},
		{
			name:         "resolves bare #{name}",
			fields:       map[string]any{"name": "foo", "homepage": "https://x/#{name}"},
			wantHomepage: "https://x/foo",
		},
		{
			name:         "resolves with surrounding whitespace",
			fields:       map[string]any{"name": "foo", "homepage": "https://x/#{ s.name }"},
			wantHomepage: "https://x/foo",
		},
		{
			name:         "resolves multiple interpolations in one field",
			fields:       map[string]any{"name": "foo", "version": "1.2", "homepage": "https://x/#{s.name}/#{s.version}"},
			wantHomepage: "https://x/foo/1.2",
		},
		{
			name:        "drops field on unresolvable expression",
			fields:      map[string]any{"name": "foo", "homepage": "https://x/#{Time.now}"},
			wantDropped: true,
		},
		{
			name:        "drops field when referenced value was not captured",
			fields:      map[string]any{"homepage": "https://x/#{s.name}"},
			wantDropped: true,
		},
		{
			name:         "leaves plain field untouched",
			fields:       map[string]any{"name": "foo", "homepage": "https://bundler.io"},
			wantHomepage: "https://bundler.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRubyInterpolationsInFields(tt.fields)
			got, present := tt.fields["homepage"].(string)
			if tt.wantDropped {
				assert.False(t, present, "expected homepage to be dropped, got %q", got)
				return
			}
			assert.Equal(t, tt.wantHomepage, got)
		})
	}
}

// Regression test for https://github.com/anchore/syft/issues/4720:
// gemspecs routinely build URL fields from Ruby string interpolation
// (e.g. "https://github.com/geemus/#{s.name}"), and syft used to pass
// those interpolations through into the emitted SBOM, producing URLs
// containing `{` and `}` that fail CycloneDX IRI validation.
func TestParseGemspec_ResolvesRubyInterpolation(t *testing.T) {
	fixture := "testdata/formatador.gemspec"
	ctx := context.TODO()
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkg := pkg.Package{
		Name:      "formatador",
		Version:   "1.1.0",
		PURL:      "pkg:gem/formatador@1.1.0",
		Locations: locations,
		Type:      pkg.GemPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation(fixture)),
		),
		Language: pkg.Ruby,
		Metadata: pkg.RubyGemspec{
			Name:    "formatador",
			Version: "1.1.0",
			Files:   []string{"lib/formatador.rb"},
			Authors: []string{"geemus (Wesley Beary)"},
			// #{s.name} should have been resolved to the captured name.
			Homepage: "https://github.com/geemus/formatador",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseGemSpecEntries, []pkg.Package{expectedPkg}, nil)
}
