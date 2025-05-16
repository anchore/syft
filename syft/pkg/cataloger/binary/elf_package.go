package binary

import (
	"context"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newELFPackage(ctx context.Context, metadata elfBinaryPackageNotes, locations file.LocationSet) pkg.Package {
	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, metadata.License)),
		PURL:      elfPackageURL(metadata),
		Type:      pkgType(metadata.Type),
		Locations: locations,
		Metadata:  metadata.ELFBinaryPackageNoteJSONPayload,
	}

	p.SetID()

	return p
}

func elfPackageURL(metadata elfBinaryPackageNotes) string {
	var qualifiers []packageurl.Qualifier

	os, osVersion := osNameAndVersionFromMetadata(metadata)

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

func osNameAndVersionFromMetadata(metadata elfBinaryPackageNotes) (string, string) {
	os := metadata.OS
	osVersion := metadata.OSVersion

	if os != "" && osVersion != "" {
		return os, osVersion
	}

	if metadata.OSCPE == "" {
		return "", ""
	}

	attrs, err := cpe.NewAttributes(metadata.OSCPE)
	if err != nil {
		log.WithFields("error", err).Trace("unable to parse cpe attributes for elf binary package")
		return "", ""
	}
	return attrs.Product, attrs.Version
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
