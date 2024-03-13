package binary

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newELFPackage(metadata elfBinaryPackageNotes, locations file.LocationSet, licenses []pkg.License) pkg.Package {
	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(metadata),
		Type:      pkg.BinaryPkg,
		Locations: locations,
		Metadata:  metadata.ELFBinaryPackageNoteJSONPayload,
	}

	p.SetID()

	return p
}

func packageURL(metadata elfBinaryPackageNotes) string {
	// TODO: what if the System value is not set?
	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		metadata.System,
		metadata.Name,
		metadata.Version,
		nil,
		"",
	).ToString()
}
