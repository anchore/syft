package homebrew

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newHomebrewPackage(name, version, desc, homepage string, locations file.LocationSet) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.HomebrewPkg,
		Locations: locations,
		Language:  pkg.Ruby,
		FoundBy:   "homebrew-cataloger",
		PURL:      packageURL(name, version),
		Metadata: pkg.HomebrewMetadata{
			Name:        name,
			FullName:    name,
			Tap:         "homebrew/core",
			Homepage:    homepage,
			Description: desc,
		},
	}

	p.SetID()
	return p
}

func packageURL(name, version string) string {
	purl := packageurl.NewPackageURL(
		"homebrew",
		"",
		name,
		version,
		nil,
		"",
	)
	return purl.ToString()
}
