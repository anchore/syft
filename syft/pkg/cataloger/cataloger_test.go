package cataloger

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var _ pkg.Cataloger = (*dummy)(nil)

type dummy struct {
	name string
}

func (d dummy) Name() string {
	return d.name
}

func (d dummy) Catalog(_ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	panic("not implemented")
}

func Test_filterCatalogers(t *testing.T) {
	largeCatalogerList := []string{
		"alpmdb-cataloger",
		"apkdb-cataloger",
		"binary-cataloger",
		"conan-cataloger",
		"dartlang-lock-cataloger",
		"dpkgdb-cataloger",
		"dotnet-deps-cataloger",
		"elixir-mix-lock-cataloger",
		"erlang-rebar-lock-cataloger",
		"go-mod-file-cataloger",
		"go-module-binary-cataloger",
		"haskell-cataloger",
		"graalvm-native-image-cataloger",
		"java-cataloger",
		"java-pom-cataloger",
		"javascript-package-cataloger",
		"javascript-lock-cataloger",
		"php-composer-installed-cataloger",
		"php-composer-lock-cataloger",
		"portage-cataloger",
		"python-index-cataloger",
		"python-package-cataloger",
		"rpm-db-cataloger",
		"rpm-file-cataloger",
		"ruby-gemfile-cataloger",
		"ruby-gemspec-cataloger",
		"rust-cargo-lock-cataloger",
		"cargo-auditable-binary-cataloger",
		"sbom-cataloger",
		"cocoapods-cataloger",
	}
	tests := []struct {
		name       string
		patterns   []string
		catalogers []string
		want       []string
	}{
		{
			name:     "no filtering",
			patterns: nil,
			catalogers: []string{
				"ruby-gemspec-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
			want: []string{
				"ruby-gemspec-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
		},
		{
			name: "exact name match",
			patterns: []string{
				"rpmdb-cataloger",
				"javascript-package-cataloger",
			},
			catalogers: []string{
				"ruby-gemspec-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
			want: []string{
				"javascript-package-cataloger",
				"rpmdb-cataloger",
			},
		},
		{
			name: "partial name match",
			patterns: []string{
				"ruby",
				"installed",
			},
			catalogers: []string{
				"ruby-gemspec-cataloger",
				"ruby-gemfile-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
			want: []string{
				"php-composer-installed-cataloger",
				"ruby-gemspec-cataloger",
				"ruby-gemfile-cataloger",
			},
		},
		{
			name: "ignore 'cataloger' keyword",
			patterns: []string{
				"cataloger",
			},
			catalogers: []string{
				"ruby-gemspec-cataloger",
				"ruby-gemfile-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
			want: []string{},
		},
		{
			name: "only some patterns match",
			patterns: []string{
				"cataloger",
				"go-module",
			},
			catalogers: []string{
				"ruby-gemspec-cataloger",
				"ruby-gemfile-cataloger",
				"python-package-cataloger",
				"php-composer-installed-cataloger",
				"javascript-package-cataloger",
				"dpkgdb-cataloger",
				"rpmdb-cataloger",
				"java-cataloger",
				"apkdb-cataloger",
				"go-module-binary-cataloger",
			},
			want: []string{
				"go-module-binary-cataloger",
			},
		},
		{
			name: "don't cross match ecosystems with matching prefix",
			patterns: []string{
				"java-cataloger",
			},
			catalogers: []string{
				"javascript-package-cataloger",
				"java-cataloger",
			},
			want: []string{
				"java-cataloger",
			},
		},
		{
			name: "don't cross match ecosystems with short, common name",
			patterns: []string{
				"go",
			},
			catalogers: largeCatalogerList,
			want: []string{
				"go-mod-file-cataloger",
				"go-module-binary-cataloger",
				//"rust-cargo-lock-cataloger",  // with naive "contains" matching
				//"cargo-auditable-binary-cataloger",  // with naive "contains" matching
			},
		},
		{
			name: "ignore partial matches",
			patterns: []string{
				"mod",
			},
			catalogers: largeCatalogerList,
			want: []string{
				"go-mod-file-cataloger",
				//"go-module-binary-cataloger", // unfortunately not a full word (this should probably be renamed)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var catalogers []pkg.Cataloger
			for _, n := range tt.catalogers {
				catalogers = append(catalogers, dummy{name: n})
			}
			got := filterCatalogers(catalogers, tt.patterns)
			var gotNames []string
			for _, g := range got {
				gotNames = append(gotNames, g.Name())
			}
			assert.ElementsMatch(t, tt.want, gotNames)
		})
	}
}

func Test_contains(t *testing.T) {
	tests := []struct {
		name              string
		enabledCatalogers []string
		catalogerName     string
		want              bool
	}{
		{
			name: "keep exact match",
			enabledCatalogers: []string{
				"php-composer-installed-cataloger",
			},
			catalogerName: "php-composer-installed-cataloger",
			want:          true,
		},
		{
			name: "match substring",
			enabledCatalogers: []string{
				"python",
			},
			catalogerName: "python-package-cataloger",
			want:          true,
		},
		{
			name: "dont match on 'cataloger'",
			enabledCatalogers: []string{
				"cataloger",
			},
			catalogerName: "python-package-cataloger",
			want:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, contains(tt.enabledCatalogers, tt.catalogerName))
		})
	}
}

func Test_hasFullWord(t *testing.T) {

	tests := []struct {
		name         string
		targetPhrase string
		candidate    string
		want         bool
	}{
		{
			name:         "exact match",
			targetPhrase: "php-composer-installed-cataloger",
			candidate:    "php-composer-installed-cataloger",
			want:         true,
		},
		{
			name:         "partial, full word match",
			targetPhrase: "composer",
			candidate:    "php-composer-installed-cataloger",
			want:         true,
		},
		{
			name:         "partial, full, multi-word match",
			targetPhrase: "php-composer",
			candidate:    "php-composer-installed-cataloger",
			want:         true,
		},
		{
			name:         "prefix match",
			targetPhrase: "php",
			candidate:    "php-composer-installed-cataloger",
			want:         true,
		},
		{
			name:         "postfix match with -cataloger suffix",
			targetPhrase: "installed",
			candidate:    "php-composer-installed-cataloger",
			want:         true,
		},
		{
			name:         "postfix match",
			targetPhrase: "installed",
			candidate:    "php-composer-installed",
			want:         true,
		},
		{
			name:         "ignore cataloger keyword",
			targetPhrase: "cataloger",
			candidate:    "php-composer-installed-cataloger",
			want:         false,
		},
		{
			name:         "ignore partial match",
			targetPhrase: "hp",
			candidate:    "php-composer-installed-cataloger",
			want:         false,
		},
		{
			name:         "ignore empty string",
			targetPhrase: "",
			candidate:    "php-composer-installed-cataloger",
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, hasFullWord(tt.targetPhrase, tt.candidate), "hasFullWord(%v, %v)", tt.targetPhrase, tt.candidate)
		})
	}
}
