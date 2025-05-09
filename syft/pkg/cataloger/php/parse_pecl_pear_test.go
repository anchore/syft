package php

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePear(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name                  string
		fixture               string
		expectedPkgs          []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "v6 format",
			fixture: "test-fixtures/memcached-v6-format.reg",
			expectedPkgs: []pkg.Package{
				{
					Name:      "memcached",
					Version:   "3.2.0",
					PURL:      "pkg:pear/pecl.php.net/memcached@3.2.0",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/memcached-v6-format.reg")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "PHP License", file.NewLocation("test-fixtures/memcached-v6-format.reg")),
					),
					Language: pkg.PHP,
					Type:     pkg.PhpPearPkg,
					Metadata: pkg.PhpPearEntry{
						Name:    "memcached",
						Channel: "pecl.php.net",
						Version: "3.2.0",
						License: []string{"PHP License"},
					},
				},
			},
		},
		{
			name:    "v5 format",
			fixture: "test-fixtures/memcached-v5-format.reg",
			expectedPkgs: []pkg.Package{
				{
					Name:      "memcached",
					Version:   "3.2.0",
					PURL:      "pkg:pear/pecl.php.net/memcached@3.2.0",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/memcached-v5-format.reg")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "PHP License", file.NewLocation("test-fixtures/memcached-v5-format.reg")),
					),
					Language: pkg.PHP,
					Type:     pkg.PhpPearPkg,
					Metadata: pkg.PhpPearEntry{ // important: missing channel
						Name:    "memcached",
						Version: "3.2.0",
						License: []string{"PHP License"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, tt.fixture, parsePear, tt.expectedPkgs, tt.expectedRelationships)
		})
	}
}

func TestParsePecl(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name                  string
		fixture               string
		expectedPkgs          []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "v6 format",
			fixture: "test-fixtures/memcached-v6-format.reg",
			expectedPkgs: []pkg.Package{
				{
					Name:      "memcached",
					Version:   "3.2.0",
					PURL:      "pkg:pear/pecl.php.net/memcached@3.2.0",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/memcached-v6-format.reg")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "PHP License", file.NewLocation("test-fixtures/memcached-v6-format.reg")),
					),
					Language: pkg.PHP,
					Type:     pkg.PhpPeclPkg, // important!
					Metadata: pkg.PhpPeclEntry{ // important!
						Name:    "memcached",
						Channel: "pecl.php.net",
						Version: "3.2.0",
						License: []string{"PHP License"},
					},
				},
			},
		},
		{
			name:    "v5 format",
			fixture: "test-fixtures/memcached-v5-format.reg",
			expectedPkgs: []pkg.Package{
				{
					Name:      "memcached",
					Version:   "3.2.0",
					PURL:      "pkg:pear/pecl.php.net/memcached@3.2.0",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/memcached-v5-format.reg")),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "PHP License", file.NewLocation("test-fixtures/memcached-v5-format.reg")),
					),
					Language: pkg.PHP,
					Type:     pkg.PhpPeclPkg, // important!
					Metadata: pkg.PhpPeclEntry{ // important!
						Name:    "memcached",
						Version: "3.2.0",
						License: []string{"PHP License"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, tt.fixture, parsePecl, tt.expectedPkgs, tt.expectedRelationships)
		})
	}
}

func Test_corruptPecl(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/php/.registry/.channel.pecl.php.net/memcached.reg").
		WithError().
		TestParser(t, parseComposerLock)
}
