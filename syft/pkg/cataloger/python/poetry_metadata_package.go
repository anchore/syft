package python

import "github.com/anchore/syft/syft/pkg"

type PoetryMetadataPackage struct {
	Name        string `toml:"name"`
	Version     string `toml:"version"`
	Category    string `toml:"category"`
	Description string `toml:"description"`
	Optional    bool   `toml:"optional"`
}

// Pkg returns the standard `pkg.Package` representation of the package referenced within the poetry.lock metadata.
func (p PoetryMetadataPackage) Pkg() pkg.Package {
	return pkg.Package{
		Name:     p.Name,
		Version:  p.Version,
		Language: pkg.Python,
		Type:     pkg.PythonPkg,
	}
}
