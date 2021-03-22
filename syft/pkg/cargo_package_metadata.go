package pkg

type CargoPackageMetadata struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source" json:"source"`
	Checksum     string   `toml:"checksum" json:"checksum"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func (p CargoPackageMetadata) Pkg() Package {
	return Package{
		Name:         p.Name,
		Version:      p.Version,
		Language:     Rust,
		Type:         RustPkg,
		MetadataType: RustCargoPackageMetadataType,
		Metadata:     p,
	}
}
