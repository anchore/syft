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
			Name:      "@actions/core",
			Version:   "1.6.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/%40actions/core@1.6.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Licenses:  []string{"MIT"},
		},
		{
			Name:      "ansi-regex",
			Version:   "3.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/ansi-regex@3.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "cowsay",
			Version:   "1.4.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/cowsay@1.4.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Licenses:  []string{"MIT"},
		},
		{
			Name:      "get-stdin",
			Version:   "5.0.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/get-stdin@5.0.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "is-fullwidth-code-point",
			Version:   "2.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/is-fullwidth-code-point@2.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "minimist",
			Version:   "0.0.10",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/minimist@0.0.10",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "optimist",
			Version:   "0.6.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/optimist@0.6.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "string-width",
			Version:   "2.1.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/string-width@2.1.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "strip-ansi",
			Version:   "4.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/strip-ansi@4.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "strip-eof",
			Version:   "1.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/strip-eof@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
		{
			Name:      "wordwrap",
			Version:   "0.0.3",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/wordwrap@0.0.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-lock").
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewJavascriptLockCataloger())
}
