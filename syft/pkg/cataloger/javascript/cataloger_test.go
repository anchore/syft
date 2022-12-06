package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func Test_JavascriptCataloger(t *testing.T) {
	locationSet := source.NewLocationSet(source.NewLocation("package-lock.json"))
	expectedPkgs := []pkg.Package{
		{
			Name:         "@actions/core",
			Version:      "1.6.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/%40actions/core@1.6.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     []string{"MIT"},
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/@actions/core/-/core-1.6.0.tgz"},
		},
		{
			Name:         "ansi-regex",
			Version:      "3.0.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/ansi-regex@3.0.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-3.0.0.tgz"},
		},
		{
			Name:         "cowsay",
			Version:      "1.4.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/cowsay@1.4.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     []string{"MIT"},
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/cowsay/-/cowsay-1.4.0.tgz"},
		},
		{
			Name:         "get-stdin",
			Version:      "5.0.1",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/get-stdin@5.0.1",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/get-stdin/-/get-stdin-5.0.1.tgz"},
		},
		{
			Name:         "is-fullwidth-code-point",
			Version:      "2.0.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/is-fullwidth-code-point@2.0.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-2.0.0.tgz"},
		},
		{
			Name:         "minimist",
			Version:      "0.0.10",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/minimist@0.0.10",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/minimist/-/minimist-0.0.10.tgz"},
		},
		{
			Name:         "optimist",
			Version:      "0.6.1",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/optimist@0.6.1",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/optimist/-/optimist-0.6.1.tgz"},
		},
		{
			Name:         "string-width",
			Version:      "2.1.1",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/string-width@2.1.1",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/string-width/-/string-width-2.1.1.tgz"},
		},
		{
			Name:         "strip-ansi",
			Version:      "4.0.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/strip-ansi@4.0.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-4.0.0.tgz"},
		},
		{
			Name:         "strip-eof",
			Version:      "1.0.0",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/strip-eof@1.0.0",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/strip-eof/-/strip-eof-1.0.0.tgz"},
		},
		{
			Name:         "wordwrap",
			Version:      "0.0.3",
			FoundBy:      "javascript-lock-cataloger",
			PURL:         "pkg:npm/wordwrap@0.0.3",
			Locations:    locationSet,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     NpmMetadata{Resolved: "https://registry.npmjs.org/wordwrap/-/wordwrap-0.0.3.tgz"},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-lock").
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewJavascriptLockCataloger())

}
