package rust

import (
	"github.com/microsoft/go-rustaudit"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func newPackageFromCargoMetadata(m pkg.RustCargoLockEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		PURL:      packageURL(m.Name, m.Version),
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Locations: file.NewLocationSet(locations...),
		FoundBy:   cargoLockCatalogerName,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func newPackageFromAudit(dep *rustaudit.Package, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      dep.Name,
		Version:   dep.Version,
		PURL:      packageURL(dep.Name, dep.Version),
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Locations: file.NewLocationSet(locations...),
		FoundBy:   cargoAuditBinaryCatalogerName,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    dep.Name,
			Version: dep.Version,
			Source:  dep.Source,
		},
	}

	p.SetID()

	return p
}

func newPackageWithEnrichment(dep *rustaudit.Package, enrichment pkg.RustCratesEnrichment, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      dep.Name,
		Version:   dep.Version,
		PURL:      packageURL(dep.Name, dep.Version),
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Locations: file.NewLocationSet(locations...),
		FoundBy:   cargoAuditBinaryCatalogerName,
		// A hasDeclaredLicense identifies the license information actually found in the Software Artifact, for example as detected by use
		// of automated tooling.
		// This field is not intended to capture license information obtained from an external source, such as a package's website.
		// Such information can be included, as needed, in the hasConcludedLicense field.
		// Source: https://spdx.github.io/spdx-spec/v2.3/package-information/#713-concluded-license-field
		Licenses: pkg.NewLicenseSet(pkg.NewLicenseFromType(enrichment.LicenseInfo, license.Concluded)),
		Metadata: pkg.RustCratesEnrichment{
			Name:             dep.Name,
			Version:          dep.Version,
			Source:           dep.Source,
			Description:      enrichment.Description,
			Supplier:         enrichment.Supplier,
			DownloadLocation: enrichment.DownloadLocation,
			Repository:       enrichment.Repository,
			LicenseInfo:      enrichment.LicenseInfo,
			CreatedBy:        enrichment.CreatedBy,
			ReleaseTime:      enrichment.ReleaseTime,
			Summary:          enrichment.Summary,
			Homepage:         enrichment.Homepage,
		},
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific rust package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeCargo,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
