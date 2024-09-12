package rust

import (
	"fmt"

	"github.com/microsoft/go-rustaudit"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/rust/internal/cargo"
)

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func newPackageFromCargoMetadata(m cargo.LockEntry, locations ...file.Location) pkg.Package {
	var cargoEntry *pkg.RustCargoEntry
	if m.CrateInfo != nil {
		cargoEntry = &pkg.RustCargoEntry{
			DownloadURL:    m.CrateInfo.DownloadLink,
			DownloadDigest: fmt.Sprintf("%x", m.CrateInfo.DownloadSha),
			Description:    m.CrateInfo.CargoToml.Package.Description,
			Homepage:       m.CrateInfo.CargoToml.Package.Homepage,
			Repository:     m.CrateInfo.CargoToml.Package.Repository,
		}
	}

	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		Locations: file.NewLocationSet(locations...),
		Licenses:  m.Licenses,
		PURL:      packageURL(m.Name, m.Version),
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustCargo{
			CargoEntry: cargoEntry,
			LockEntry:  &m.RustCargoLockEntry,
		},
	}

	p.SetID()

	return p
}

func newPackagesFromAudit(location file.Location, versionInfo rustaudit.VersionInfo) []pkg.Package {
	var pkgs []pkg.Package

	for _, dep := range versionInfo.Packages {
		p := newPackageFromAudit(&dep, location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if pkg.IsValid(&p) && dep.Kind == rustaudit.Runtime {
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

func newPackageFromAudit(dep *rustaudit.Package, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      dep.Name,
		Version:   dep.Version,
		PURL:      packageURL(dep.Name, dep.Version),
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Locations: file.NewLocationSet(locations...),
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    dep.Name,
			Version: dep.Version,
			Source:  dep.Source,
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
