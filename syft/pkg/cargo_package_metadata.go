package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*CargoPackageMetadata)(nil)

type CargoPackageMetadata struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source" json:"source"`
	Checksum     string   `toml:"checksum" json:"checksum"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func (p CargoPackageMetadata) Pkg() *Package {
	return &Package{
		Name:         p.Name,
		Version:      p.Version,
		Language:     Rust,
		Type:         RustPkg,
		MetadataType: RustCargoPackageMetadataType,
		Metadata:     p,
	}
}

// PackageURL returns the PURL for the specific rust package (see https://github.com/package-url/purl-spec)
func (p CargoPackageMetadata) PackageURL(_ *linux.Release) string {
	return packageurl.NewPackageURL(
		"cargo",
		"",
		p.Name,
		p.Version,
		nil,
		"",
	).ToString()
}
