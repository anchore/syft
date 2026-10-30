package ruby

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGemfileLockEntries(t *testing.T) {
	fixture := "testdata/Gemfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	var expectedPkgs = []pkg.Package{
		{Name: "actionmailer", Version: "4.1.1", PURL: "pkg:gem/actionmailer@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "actionpack", Version: "4.1.1", PURL: "pkg:gem/actionpack@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "actionview", Version: "4.1.1", PURL: "pkg:gem/actionview@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activemodel", Version: "4.1.1", PURL: "pkg:gem/activemodel@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activerecord", Version: "4.1.1", PURL: "pkg:gem/activerecord@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activesupport", Version: "4.1.1", PURL: "pkg:gem/activesupport@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "arel", Version: "5.0.1.20140414130214", PURL: "pkg:gem/arel@5.0.1.20140414130214", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "bootstrap-sass", Version: "3.1.1.1", PURL: "pkg:gem/bootstrap-sass@3.1.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "builder", Version: "3.2.2", PURL: "pkg:gem/builder@3.2.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-rails", Version: "4.0.1", PURL: "pkg:gem/coffee-rails@4.0.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-script", Version: "2.2.0", PURL: "pkg:gem/coffee-script@2.2.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-script-source", Version: "1.7.0", PURL: "pkg:gem/coffee-script-source@1.7.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "erubis", Version: "2.7.0", PURL: "pkg:gem/erubis@2.7.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "execjs", Version: "2.0.2", PURL: "pkg:gem/execjs@2.0.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "google-cloud-errors", Version: "1.3.0", PURL: "pkg:gem/google-cloud-errors@1.3.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "hike", Version: "1.2.3", PURL: "pkg:gem/hike@1.2.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "i18n", Version: "0.6.9", PURL: "pkg:gem/i18n@0.6.9", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "jbuilder", Version: "2.0.7", PURL: "pkg:gem/jbuilder@2.0.7", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "jquery-rails", Version: "3.1.0", PURL: "pkg:gem/jquery-rails@3.1.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "json", Version: "1.8.1", PURL: "pkg:gem/json@1.8.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "kgio", Version: "2.9.2", PURL: "pkg:gem/kgio@2.9.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "libv8", Version: "3.16.14.3", PURL: "pkg:gem/libv8@3.16.14.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mail", Version: "2.5.4", PURL: "pkg:gem/mail@2.5.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mime-types", Version: "1.25.1", PURL: "pkg:gem/mime-types@1.25.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "minitest", Version: "5.3.4", PURL: "pkg:gem/minitest@5.3.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "multi_json", Version: "1.10.1", PURL: "pkg:gem/multi_json@1.10.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mysql2", Version: "0.3.16", PURL: "pkg:gem/mysql2@0.3.16", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "polyglot", Version: "0.3.4", PURL: "pkg:gem/polyglot@0.3.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rack", Version: "1.5.2", PURL: "pkg:gem/rack@1.5.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rack-test", Version: "0.6.2", PURL: "pkg:gem/rack-test@0.6.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rails", Version: "4.1.1", PURL: "pkg:gem/rails@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "railties", Version: "4.1.1", PURL: "pkg:gem/railties@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "raindrops", Version: "0.13.0", PURL: "pkg:gem/raindrops@0.13.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rake", Version: "10.3.2", PURL: "pkg:gem/rake@10.3.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rdoc", Version: "4.1.1", PURL: "pkg:gem/rdoc@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "ref", Version: "1.0.5", PURL: "pkg:gem/ref@1.0.5", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sass", Version: "3.2.19", PURL: "pkg:gem/sass@3.2.19", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sass-rails", Version: "4.0.3", PURL: "pkg:gem/sass-rails@4.0.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sdoc", Version: "0.4.0", PURL: "pkg:gem/sdoc@0.4.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "spring", Version: "1.1.3", PURL: "pkg:gem/spring@1.1.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sprockets", Version: "2.11.0", PURL: "pkg:gem/sprockets@2.11.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sprockets-rails", Version: "2.1.3", PURL: "pkg:gem/sprockets-rails@2.1.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sqlite3", Version: "1.3.9", PURL: "pkg:gem/sqlite3@1.3.9", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "therubyracer", Version: "0.12.1", PURL: "pkg:gem/therubyracer@0.12.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "thor", Version: "0.19.1", PURL: "pkg:gem/thor@0.19.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "thread_safe", Version: "0.3.3", PURL: "pkg:gem/thread_safe@0.3.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "tilt", Version: "1.4.1", PURL: "pkg:gem/tilt@1.4.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "treetop", Version: "1.4.15", PURL: "pkg:gem/treetop@1.4.15", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "turbolinks", Version: "3.0.0", PURL: "pkg:gem/turbolinks@3.0.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "tzinfo", Version: "1.2.0", PURL: "pkg:gem/tzinfo@1.2.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "uglifier", Version: "2.5.0", PURL: "pkg:gem/uglifier@2.5.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "unicorn", Version: "4.8.3", PURL: "pkg:gem/unicorn@4.8.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
	}

	// gemDeps mirrors the dependency lines listed under each gem in
	// testdata/Gemfile.lock, in file order. It deliberately preserves entries as
	// written: "bundler" (which is not itself a locked gem) and treetop's
	// duplicate "polyglot" are recorded here even though the resolver drops them
	// when building relationships.
	gemDeps := map[string][]string{
		"actionmailer":    {"actionpack", "actionview", "mail"},
		"actionpack":      {"actionview", "activesupport", "rack", "rack-test"},
		"actionview":      {"activesupport", "builder", "erubis"},
		"activemodel":     {"activesupport", "builder"},
		"activerecord":    {"activemodel", "activesupport", "arel"},
		"activesupport":   {"i18n", "json", "minitest", "thread_safe", "tzinfo"},
		"bootstrap-sass":  {"sass"},
		"coffee-rails":    {"coffee-script", "railties"},
		"coffee-script":   {"coffee-script-source", "execjs"},
		"jbuilder":        {"activesupport", "multi_json"},
		"jquery-rails":    {"railties", "thor"},
		"mail":            {"mime-types", "treetop"},
		"rack-test":       {"rack"},
		"rails":           {"actionmailer", "actionpack", "actionview", "activemodel", "activerecord", "activesupport", "bundler", "railties", "sprockets-rails"},
		"railties":        {"actionpack", "activesupport", "rake", "thor"},
		"rdoc":            {"json"},
		"sass-rails":      {"railties", "sass", "sprockets", "sprockets-rails"},
		"sdoc":            {"json", "rdoc"},
		"sprockets":       {"hike", "multi_json", "rack", "tilt"},
		"sprockets-rails": {"actionpack", "activesupport", "sprockets"},
		"therubyracer":    {"libv8", "ref"},
		"treetop":         {"polyglot", "polyglot"},
		"turbolinks":      {"coffee-rails"},
		"tzinfo":          {"thread_safe"},
		"uglifier":        {"execjs", "json"},
		"unicorn":         {"kgio", "rack", "raindrops"},
	}

	// directGems mirrors the DEPENDENCIES section of testdata/Gemfile.lock, the
	// gems the Gemfile declares. google-cloud-errors and turbolinks are written
	// with a trailing "!" there because they come from a git source.
	directGems := strset.New(
		"bootstrap-sass", "coffee-rails", "google-cloud-errors", "jbuilder", "jquery-rails",
		"mysql2", "rails", "sass-rails", "sdoc", "spring", "sqlite3", "therubyracer",
		"turbolinks", "uglifier", "unicorn",
	)

	for i := range expectedPkgs {
		name := expectedPkgs[i].Name
		expectedPkgs[i].Metadata = pkg.RubyGemfileLockEntry{
			Name:         name,
			Version:      expectedPkgs[i].Version,
			Dependencies: gemDeps[name],
			Direct:       directGems.Has(name),
		}
		expectedPkgs[i].SetID()
	}

	// each locked dependency of a gem is one dependency-of relationship: bundler is
	// not locked so it has none, and treetop's duplicate polyglot gives one.
	pkgsByName := map[string]pkg.Package{}
	for _, p := range expectedPkgs {
		pkgsByName[p.Name] = p
	}
	var expectedRelationships []artifact.Relationship
	for name, deps := range gemDeps {
		resolved := strset.New()
		for _, dep := range deps {
			depPkg, locked := pkgsByName[dep]
			if !locked || resolved.Has(dep) {
				continue
			}
			resolved.Add(dep)
			expectedRelationships = append(expectedRelationships, artifact.Relationship{
				From: depPkg,
				To:   pkgsByName[name],
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		Expects(expectedPkgs, expectedRelationships).
		TestParser(t, parseGemFileLockEntries)
}

func TestParseGemfileLockEntries_Direct(t *testing.T) {
	tests := []struct {
		name     string
		lockfile string
		want     map[string]bool
	}{
		{
			name: "every platform variant of a declared gem is direct",
			lockfile: `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)

PLATFORMS
  arm64-darwin
  x86_64-linux

DEPENDENCIES
  nokogiri (~> 1.16)

BUNDLED WITH
   2.5.6
`,
			want: map[string]bool{
				"nokogiri@1.16.0-arm64-darwin": true,
				"nokogiri@1.16.0-x86_64-linux": true,
				"racc@1.7.3":                   false,
			},
		},
		{
			name: "git and path sources are written with a trailing bang",
			lockfile: `GIT
  remote: https://github.com/rails/turbolinks.git
  revision: 0123456789abcdef
  specs:
    turbolinks (3.0.0)
      coffee-rails

PATH
  remote: engines/billing
  specs:
    billing (0.1.0)
      rails (>= 7.0)

GEM
  remote: https://rubygems.org/
  specs:
    coffee-rails (4.0.1)
    rails (7.1.3)

PLATFORMS
  ruby

DEPENDENCIES
  billing!
  rails (~> 7.1)
  turbolinks!
`,
			want: map[string]bool{
				"turbolinks@3.0.0":   true,
				"billing@0.1.0":      true,
				"coffee-rails@4.0.1": false,
				"rails@7.1.3":        true,
			},
		},
		{
			name: "checksum, ruby version and bundled-with lines are not dependencies",
			lockfile: `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.9)
    rake (13.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake

CHECKSUMS
  rack (3.0.9) sha256=abc
  rake (13.1.0) sha256=def

RUBY VERSION
   ruby 3.3.0p0

BUNDLED WITH
   2.5.6
`,
			want: map[string]bool{
				"rack@3.0.9":  false,
				"rake@13.1.0": true,
			},
		},
		{
			name: "a declared gem with no locked spec adds no package",
			lockfile: `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.1.0)

DEPENDENCIES
  ghost
  rake
`,
			want: map[string]bool{
				"rake@13.1.0": true,
			},
		},
		{
			name: "no dependencies section marks nothing direct",
			lockfile: `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.9)
    rake (13.1.0)
`,
			want: map[string]bool{
				"rack@3.0.9":  false,
				"rake@13.1.0": false,
			},
		},
		{
			name:     "windows line endings",
			lockfile: "GEM\r\n  remote: https://rubygems.org/\r\n  specs:\r\n    rack (3.0.9)\r\n    rake (13.1.0)\r\n      rack (>= 3)\r\n\r\nDEPENDENCIES\r\n  rake\r\n",
			want: map[string]bool{
				"rack@3.0.9":  false,
				"rake@13.1.0": true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := file.NewLocationReadCloser(file.NewLocation("Gemfile.lock"), io.NopCloser(strings.NewReader(tt.lockfile)))

			pkgs, _, err := parseGemFileLockEntries(context.Background(), nil, nil, reader)

			require.NoError(t, err)
			got := map[string]bool{}
			for _, p := range pkgs {
				metadata, ok := p.Metadata.(pkg.RubyGemfileLockEntry)
				require.True(t, ok, "%s has metadata %T", p.Name, p.Metadata)
				got[p.Name+"@"+p.Version] = metadata.Direct
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
