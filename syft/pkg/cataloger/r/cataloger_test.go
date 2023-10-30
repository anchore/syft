package r

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestRPackageCataloger(t *testing.T) {
	expectedPkgs := []pkg.Package{
		{
			Name:      "base",
			Version:   "4.3.0",
			FoundBy:   "r-package-cataloger",
			Locations: file.NewLocationSet(file.NewLocation("base/DESCRIPTION")),
			Licenses:  pkg.NewLicenseSet([]pkg.License{pkg.NewLicense("Part of R 4.3.0")}...),
			Language:  pkg.R,
			Type:      pkg.Rpkg,
			PURL:      "pkg:cran/base@4.3.0",
			Metadata: pkg.RDescription{
				Title:       "The R Base Package",
				Description: "Base R functions.",
				Author:      "R Core Team and contributors worldwide",
				Maintainer:  "R Core Team <do-use-Contact-address@r-project.org>",
				Built:       "R 4.3.0; ; 2023-04-21 11:33:09 UTC; unix",
				Suggests:    []string{"methods"},
			},
		},
		{
			Name:      "stringr",
			Version:   "1.5.0.9000",
			FoundBy:   "r-package-cataloger",
			Locations: file.NewLocationSet(file.NewLocation("stringr/DESCRIPTION")),
			Licenses:  pkg.NewLicenseSet([]pkg.License{pkg.NewLicense("MIT")}...),
			Language:  pkg.R,
			Type:      pkg.Rpkg,
			PURL:      "pkg:cran/stringr@1.5.0.9000",
			Metadata: pkg.RDescription{
				Title:       "Simple, Consistent Wrappers for Common String Operations",
				Description: "A consistent, simple and easy to use set of wrappers around the fantastic 'stringi' package. All function and argument names (and positions) are consistent, all functions deal with \"NA\"'s and zero length vectors in the same way, and the output from one function is easy to feed into the input of another.",
				URL:         []string{"https://stringr.tidyverse.org", "https://github.com/tidyverse/stringr"},
				Imports: []string{
					"cli", "glue (>= 1.6.1)", "lifecycle (>= 1.0.3)", "magrittr",
					"rlang (>= 1.0.0)", "stringi (>= 1.5.3)", "vctrs (>= 0.4.0)",
				},
				Depends:  []string{"R (>= 3.3)"},
				Suggests: []string{"covr", "dplyr", "gt", "htmltools", "htmlwidgets", "knitr", "rmarkdown", "testthat (>= 3.0.0)", "tibble"},
			},
		},
	}
	// TODO: relationships are not under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.NewCatalogTester().FromDirectory(t, "test-fixtures/installed").Expects(expectedPkgs, expectedRelationships).TestCataloger(t, NewPackageCataloger())
}
