package pkg

type CargoMetadata struct {
	Packages []CargoPackageMetadata `toml:"package"`
}

// Pkgs returns all of the packages referenced within the Cargo.lock metadata.
func (m CargoMetadata) Pkgs() []*Package {
	pkgs := make([]*Package, 0)

	for _, p := range m.Packages {
		if p.Dependencies == nil {
			p.Dependencies = make([]string, 0)
		}
		pkgs = append(pkgs, p.Pkg())
	}

	return pkgs
}
