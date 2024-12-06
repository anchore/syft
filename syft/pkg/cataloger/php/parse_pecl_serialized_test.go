package php

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePeclSerialized(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/memcached.reg"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "memcached",
			Version:   "3.2.0",
			PURL:      "pkg:pecl/memcached@3.2.0",
			Locations: locations,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromLocations("PHP License", file.NewLocation(fixture)),
			),
			Language: pkg.PHP,
			Type:     pkg.PhpPeclPkg,
			Metadata: pkg.PhpPeclEntry{
				Name:    "memcached",
				Version: "3.2.0",
				License: []string{"PHP License"},
			},
		},
	}
	pkgtest.TestFileParser(t, fixture, parsePeclSerialized, expectedPkgs, expectedRelationships)
}

func Test_corruptPecl(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/php/.registry/.channel.pecl.php.net/memcached.reg").
		WithError().
		TestParser(t, parseComposerLock)
}
