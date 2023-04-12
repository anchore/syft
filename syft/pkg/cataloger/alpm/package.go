package alpm

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(m *parsedData, release *linux.Release, locations ...source.Location) pkg.Package {
	// ALPM only passes a single location
	// We use this as the "declared" license location
	var licenseLocation source.Location
	if len(locations) > 0 {
		licenseLocation = locations[0]
	}

	// default to empty list; not nil field
	licenses := make([]pkg.License, 0)
	licenseCandidates := strings.Split(m.Licenses, "\n")
	for _, l := range licenseCandidates {
		if l != "" {
			licenses = append(licenses, pkg.NewLicense(l, "", licenseLocation))
		}
	}

	p := pkg.Package{
		Name:         m.Package,
		Version:      m.Version,
		Locations:    source.NewLocationSet(locations...),
		Licenses:     licenses,
		Type:         pkg.AlpmPkg,
		PURL:         packageURL(m, release),
		MetadataType: pkg.AlpmMetadataType,
		Metadata: pkg.AlpmMetadata{
			BasePackage:  m.BasePackage,
			Package:      m.Package,
			Version:      m.Version,
			Description:  m.Description,
			Architecture: m.Architecture,
			Size:         m.Size,
			Packager:     m.Packager,
			URL:          m.URL,
			Validation:   m.Validation,
			Reason:       m.Reason,
			Files:        m.Files,
			Backup:       m.Backup,
		},
	}
	p.SetID()
	return p
}

func packageURL(m *parsedData, distro *linux.Release) string {
	if distro == nil || distro.ID != "arch" {
		// note: there is no namespace variation (like with debian ID_LIKE for ubuntu ID, for example)
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	if m.BasePackage != "" {
		qualifiers[pkg.PURLQualifierUpstream] = m.BasePackage
	}

	return packageurl.NewPackageURL(
		"alpm", // `alpm` for Arch Linux and other users of the libalpm/pacman package manager. (see https://github.com/package-url/purl-spec/pull/164)
		distro.ID,
		m.Package,
		m.Version,
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
