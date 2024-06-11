package rust

import "github.com/anchore/syft/syft/pkg"

type packageID struct {
	Name    string
	Version string
}

type packageWrap struct {
	spdxPackage pkg.Package
	rustPackage RustCargoLockEntry
}
