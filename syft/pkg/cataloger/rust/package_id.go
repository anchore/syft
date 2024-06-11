package rust

import "github.com/anchore/syft/syft/pkg"

type PackageID struct {
	Name    string
	Version string
}

type Package struct {
	spdxPackage pkg.Package
	rustPackage CargoLockEntry
}
