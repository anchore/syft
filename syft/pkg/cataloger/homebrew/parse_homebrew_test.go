package homebrew

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ParseHomebrewPackage(t *testing.T) {

	tests := []struct {
		name     string
		fixture  string
		expected pkg.Package
	}{
		{
			name:    "syft tap",
			fixture: "test-fixtures/formulas/syft/1.23.1/.brew/syft.rb",
			expected: pkg.Package{
				Name:    "syft",
				Version: "1.23.1",
				Type:    pkg.HomebrewPkg,
				Locations: file.NewLocationSet(
					file.NewLocation("test-fixtures/formulas/syft/1.23.1/.brew/syft.rb").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				),
				Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValues("Apache License 2.0")...),
				FoundBy:  "homebrew-cataloger",
				PURL:     "pkg:brew/syft@1.23.1",
				Metadata: pkg.HomebrewFormula{
					Homepage:    "https://github.com/anchore/syft",
					Description: "A tool that generates a Software Bill Of Materials (SBOM) from container images and filesystems",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, test.fixture, parseHomebrewPackage, []pkg.Package{test.expected}, nil)
		})
	}
}
