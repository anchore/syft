package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseYarnBerry(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn-berry/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,
			PURL:      "pkg:npm/atob@2.1.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "c0n-fab_u.laTION",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/c0n-fab_u.laTION@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseYarnLock, expectedPkgs, expectedRelationships)
}

func TestParseYarnLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,

			PURL:     "pkg:npm/atob@2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			Locations: locations,
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "c0n-fab_u.laTION",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/c0n-fab_u.laTION@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseYarnLock, expectedPkgs, expectedRelationships)
}
