package cataloger

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var _ Cataloger = (*dummy)(nil)

type dummy struct {
	name string
}

func (d dummy) Name() string {
	return d.name
}

func (d dummy) Catalog(_ source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	panic("not implemented")
}

func Test_filterCatalogers(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var catalogers []Cataloger
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
	type args struct {
	}
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
