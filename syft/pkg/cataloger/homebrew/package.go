package homebrew

import (
	"context"
	"path"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

func newHomebrewPackage(ctx context.Context, resolver file.Resolver, pd parsedHomebrewData, formulaLocation file.Location) pkg.Package {
	var lics []pkg.License
	if pd.License != "" {
		lics = append(lics, pkg.NewLicensesFromValues(pd.License)...)
	} else {
		// sometimes licenses are included in the parent directory
		lics = licenses.FindInDirs(ctx, resolver, path.Dir(formulaLocation.Path()))
	}

	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Type:      pkg.HomebrewPkg,
		Locations: file.NewLocationSet(formulaLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(lics...),
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
