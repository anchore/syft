package homebrew

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newHomebrewPackage(pd parsedHomebrewData, formulaLocation file.Location) pkg.Package {
	var licenses []string
	if pd.License != "" {
		licenses = append(licenses, pd.License)
	}

	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Type:      pkg.HomebrewPkg,
		Locations: file.NewLocationSet(formulaLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromValues(licenses...)...),
		FoundBy:   "homebrew-cataloger",
		PURL:      packageURL(pd.Name, pd.Version),
		Metadata: pkg.HomebrewFormula{
			Tap:         pd.Tap,
			Homepage:    pd.Homepage,
			Description: pd.Desc,
		},
	}

	p.SetID()
	return p
}

func packageURL(name, version string) string {
	purl := packageurl.NewPackageURL(
		"brew",
		"",
		name,
		version,
		nil,
		"",
	)
	return purl.ToString()
}
