package rust

import (
	"github.com/microsoft/go-rustaudit"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func newPackageFromCargoMetadata(m pkg.CargoPackageMetadata, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(m.Name, m.Version),
		Language:     pkg.Rust,
		Type:         pkg.RustPkg,
		MetadataType: pkg.RustCargoPackageMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func newPackagesFromAudit(location source.Location, versionInfo rustaudit.VersionInfo) []pkg.Package {
	var pkgs []pkg.Package

	for _, dep := range versionInfo.Packages {
		dep := dep
		p := newPackageFromAudit(&dep, location.Annotate(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if pkg.IsValid(&p) && dep.Kind == rustaudit.Runtime {
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

func newPackageFromAudit(dep *rustaudit.Package, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         dep.Name,
		Version:      dep.Version,
		PURL:         packageURL(dep.Name, dep.Version),
		Language:     pkg.Rust,
		Type:         pkg.RustPkg,
		Locations:    source.NewLocationSet(locations...),
		MetadataType: pkg.RustCargoPackageMetadataType,
		Metadata: pkg.CargoPackageMetadata{
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
