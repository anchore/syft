package rust

import "github.com/anchore/syft/syft/pkg"

type CargoMetadataPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func (p CargoMetadataPackage) Pkg() pkg.Package {
	return pkg.Package{
		Name:     p.Name,
		Version:  p.Version,
		Language: pkg.Rust,
		Type:     pkg.RustPkg,
	}
}
