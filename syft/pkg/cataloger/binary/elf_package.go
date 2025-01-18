package binary

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newELFPackages(metadata elfBinaryPackageNotes, locations file.LocationSet) ([]pkg.Package, []artifact.Relationship) {
	parentPkg := newELFPackage(metadata.elfPackageCore, locations)
	pkgs := []pkg.Package{parentPkg}
	var relationships []artifact.Relationship
	for _, depMetadata := range metadata.Dependencies {
		dep := newELFPackage(depMetadata, locations)
		pkgs = append(pkgs, dep)
		relationships = append(relationships, artifact.Relationship{
			From: dep,
			To:   parentPkg,
			Type: artifact.DependencyOfRelationship,
		})
	}

	return pkgs, relationships
}

func newELFPackage(metadata elfPackageCore, locations file.LocationSet) pkg.Package {
	var cpes []cpe.CPE
	if metadata.CPE != "" {
		c, err := cpe.New(metadata.CPE, cpe.DeclaredSource)
		if err != nil {
			log.WithFields("error", err, "cpe", metadata.CPE).Trace("unable to parse cpe for elf binary package")
		} else {
			cpes = append(cpes, c)
		}
	}

	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(metadata.License)),
		PURL:      packageURL(metadata),
		Type:      pkgType(metadata.Type),
		CPEs:      cpes,
		Locations: locations,
		Metadata:  metadata.ELFBinaryPackageNoteJSONPayload,
	}

	p.SetID()

	return p
}

func packageURL(metadata elfPackageCore) string {
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

func osNameAndVersionFromMetadata(metadata elfPackageCore) (string, string) {
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
