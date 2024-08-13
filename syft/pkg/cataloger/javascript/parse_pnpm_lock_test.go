package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePnpmLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "nanoid",
			Version:   "3.3.4",
			PURL:      "pkg:npm/nanoid@3.3.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "picocolors",
			Version:   "1.0.0",
			PURL:      "pkg:npm/picocolors@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "source-map-js",
			Version:   "1.0.2",
			PURL:      "pkg:npm/source-map-js@1.0.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@bcoe/v8-coverage",
			Version:   "0.2.3",
			PURL:      "pkg:npm/%40bcoe/v8-coverage@0.2.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestParsePnpmV6Lock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm-v6/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@testing-library/jest-dom",
			Version:   "5.16.5",
			PURL:      "pkg:npm/%40testing-library/jest-dom@5.16.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@testing-library/react",
			Version:   "13.4.0",
			PURL:      "pkg:npm/%40testing-library/react@13.4.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@testing-library/user-event",
			Version:   "13.5.0",
			PURL:      "pkg:npm/%40testing-library/user-event@13.5.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "react",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "react-dom",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react-dom@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "web-vitals",
			Version:   "2.1.4",
			PURL:      "pkg:npm/web-vitals@2.1.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@babel/core",
			Version:   "7.21.4",
			PURL:      "pkg:npm/%40babel/core@7.21.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "@types/eslint",
			Version:   "8.37.0",
			PURL:      "pkg:npm/%40types/eslint@8.37.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "read-cache",
			Version:   "1.0.0",
			PURL:      "pkg:npm/read-cache@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "schema-utils",
			Version:   "3.1.2",
			PURL:      "pkg:npm/schema-utils@3.1.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parsePnpmLock, expectedPkgs, expectedRelationships)
}

func Test_corruptPnpmLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/pnpm-lock.yaml").
		WithError().
		TestParser(t, parsePnpmLock)
}
