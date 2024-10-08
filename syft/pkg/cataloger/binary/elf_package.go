package binary

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newELFPackage(metadata elfBinaryPackageNotes, locations file.LocationSet) pkg.Package {
	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(metadata.License)),
		PURL:      packageURL(metadata),
		Type:      pkgType(metadata.Type),
		Locations: locations,
		Metadata:  metadata.ELFBinaryPackageNoteJSONPayload,
	}

	p.SetID()

	return p
}

func packageURL(metadata elfBinaryPackageNotes) string {
	var qualifiers []packageurl.Qualifier

	os := metadata.OS
	osVersion := metadata.OSVersion

	var atts cpe.Attributes
	atts, err := cpe.NewAttributes(metadata.OSCPE)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse cpe attributes for elf binary package")
	}
	// only "upgrade" the OS information if there is something more specific to use in it's place
	if os == "" && osVersion == "" || os == "" && atts.Version != "" || atts.Product != "" && osVersion == "" {
		os = atts.Product
		osVersion = atts.Version
	}

	if os != "" {
		osQualifier := os
		if osVersion != "" {
			osQualifier += "-" + osVersion
		}
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "distro",
			Value: osQualifier,
		})
	}

	ty := purlDistroType(metadata.Type)

	namespace := os

	if ty == packageurl.TypeGeneric || os == "" {
		namespace = metadata.System
	}

	return packageurl.NewPackageURL(
		ty,
		namespace,
		metadata.Name,
		metadata.Version,
		qualifiers,
		"",
	).ToString()
}

const alpmType = "alpm"

func purlDistroType(ty string) string {
	switch ty {
	case "rpm":
		return packageurl.TypeRPM
	case "deb":
		return packageurl.TypeDebian
	case "apk":
		return packageurl.TypeAlpine
	case alpmType:
		return alpmType
	}
	return packageurl.TypeGeneric
}

func pkgType(ty string) pkg.Type {
	switch ty {
	case "rpm":
		return pkg.RpmPkg
	case "deb":
		return pkg.DebPkg
	case "apk":
		return pkg.ApkPkg
	case alpmType:
		return pkg.AlpmPkg
	}
	return pkg.BinaryPkg
}
