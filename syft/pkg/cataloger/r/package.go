package r

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(pd parseData, locations ...source.Location) pkg.Package {
	locationSet := source.NewLocationSet()
	for _, loc := range locations {
		locationSet.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}
	result := pkg.Package{
		Name:         pd.Package,
		Version:      pd.Version,
		FoundBy:      catalogerName,
		Locations:    locationSet,
		Licenses:     []string{pd.License},
		Language:     pkg.R,
		Type:         pkg.Rpkg,
		PURL:         packageURL(pd),
		MetadataType: pkg.RDescriptionFileMetadataType,
		Metadata:     pd.RDescriptionFileMetadata,
	}

	result.FoundBy = catalogerName

	result.Licenses = []string{pd.License}
	result.Version = pd.Version
	result.SetID()
	return result
}

func packageURL(m parseData) string {
	return packageurl.NewPackageURL("cran", "", m.Package, m.Version, nil, "").ToString()
}
