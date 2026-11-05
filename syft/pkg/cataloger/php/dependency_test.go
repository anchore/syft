package php

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func Test_composerDependencySpecifier(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "no dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerLockEntry{
					Name: "foo",
					Require: map[string]string{},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
				},
			},
		},
		{
			name: "with required dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerLockEntry{
					Name: "foo",
					Require: map[string]string{
						"bar": "1.2.3",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar"},
				},
			},
		},
		{
			name: "with provides and replaces",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerLockEntry{
					Name: "foo",
					Require: map[string]string{
						"bar": "1.2.3",
					},
					Provide: map[string]string{
						"baz": "1.2.3",
					},
					Replace: map[string]string{
						"qux": "1.2.3",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo", "baz",	"qux"},
					Requires: []string{"bar"},
				},
			},
		},
		{
			name: "installed no dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerInstalledEntry{
					Name: "foo",
					Require: map[string]string{},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
				},
			},
		},
		{
			name: "installed with required dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerInstalledEntry{
					Name: "foo",
					Require: map[string]string{
						"bar": "1.2.3",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar"},
				},
			},
		},
		{
			name: "installed with provides and replaces",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PhpComposerInstalledEntry{
					Name: "foo",
					Require: map[string]string{
						"bar": "1.2.3",
					},
					Provide: map[string]string{
						"baz": "1.2.3",
					},
					Replace: map[string]string{
						"qux": "1.2.3",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo", "baz",	"qux"},
					Requires: []string{"bar"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, composerDependencySpecifier(tt.p))
		})
	}
}

func Test_composerLockDependencySpecifier_lockfile(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []dependency.Specification
	}{
		{
			name:    "composer.lock with dependencies and provides",
			fixture: "./testdata/composer.lock",
			want: []dependency.Specification{
				// packages are in the order they appear in the lock file
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"adoy/fastcgi-client"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"alcaeus/mongo-php-adapter", "ext-mongo"},
						Requires: []string{"ext-ctype", "ext-hash", "ext-mongodb", "mongodb/mongodb", "php"},
					},
				},
			},
		},
		{
			name:    "composer.lock with replace",
			fixture: "./testdata/composer.replace.lock",
			want: []dependency.Specification{
				// packages are in the order they appear in the lock file
				{
					ProvidesRequires:	dependency.ProvidesRequires{
						Provides: []string{"paragonie/random_compat"},
						Requires: []string{"php"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"ramsey/uuid", "rhumsaa/uuid"},
						Requires: []string{"paragonie/random_compat", "php"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"zircote/rhubarb"},
						Requires: []string{"rhumsaa/uuid"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fh, err := os.Open(tt.fixture)
			require.NoError(t, err)

			pkgs, _, err := parseComposerLock(context.TODO(), nil, nil, file.NewLocationReadCloser(file.NewLocation(tt.fixture), fh))
			require.NoError(t, err)

			var got []dependency.Specification
			for _, p := range pkgs {
				specifier := composerDependencySpecifier(p)
				slices.Sort(specifier.Provides)
				slices.Sort(specifier.Requires)
				got = append(got, specifier)
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("wrong result (-want +got):\n%s", d)
			}
		})
	}
}

func Test_composerInstalledDependencySpecifier_lockfile(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []dependency.Specification
	}{
		{
			name:    "composer v1 installed.json",
			fixture: "./testdata/vendor/composer_1/installed.json",
			want: []dependency.Specification{
				// packages are in the order they appear in the installed.json file
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"asm89/stack-cors"},
						Requires: []string{"php", "symfony/http-foundation", "symfony/http-kernel"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"behat/mink"},
						Requires: []string{"php", "symfony/css-selector"},
					},
				},
			},
		},
		{
			name:    "composer v2 installed.json",
			fixture: "./testdata/vendor/composer_2/installed.json",
			want: []dependency.Specification{
				// packages are in the order they appear in the installed.json file
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"asm89/stack-cors"},
						Requires: []string{"php", "symfony/http-foundation", "symfony/http-kernel"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"behat/mink"},
						Requires: []string{"php", "symfony/css-selector"},
					},
				},
			},
		},
		{
			name:    "composer v2 installed.json replace",
			fixture: "./testdata/vendor/composer_2/installed.replace.json",
			want: []dependency.Specification{
				// packages are in the order they appear in the lock file
				{
					ProvidesRequires:	dependency.ProvidesRequires{
						Provides: []string{"paragonie/random_compat"},
						Requires: []string{"php"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"ramsey/uuid", "rhumsaa/uuid"},
						Requires: []string{"paragonie/random_compat", "php"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"zircote/rhubarb"},
						Requires: []string{"rhumsaa/uuid"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fh, err := os.Open(tt.fixture)
			require.NoError(t, err)

			pkgs, _, err := parseInstalledJSON(context.TODO(), nil, nil, file.NewLocationReadCloser(file.NewLocation(tt.fixture), fh))
			require.NoError(t, err)

			var got []dependency.Specification
			for _, p := range pkgs {
				specifier := composerDependencySpecifier(p)
				slices.Sort(specifier.Provides)
				slices.Sort(specifier.Requires)
				got = append(got, specifier)
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("wrong result (-want +got):\n%s", d)
			}
		})
	}
}
