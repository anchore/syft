package pkg

type CargoPackageMetadata struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source,omitempty" json:"source,omitempty"`
	Checksum     string   `toml:"checksum,omitempty" json:"checksum,omitempty"`
	Dependencies []string `toml:"dependencies,omitempty" json:"dependencies,omitempty"`
}

// Pkg returns the standard `pkg.Package` representation of the package referenced within the Cargo.lock metadata.
func (p CargoPackageMetadata) Pkg() Package {
	return Package{
		Name:         p.Name,
		Version:      p.Version,
		Language:     Rust,
		Type:         RustPkg,
		MetadataType: RustCrateMetadataType,
		Metadata:     p,
	}
}
