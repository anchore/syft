package dotnet

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDotnetDepsCataloger returns a cataloger based on deps.json files.
func NewDotnetDepsCataloger() pkg.Cataloger {
	return &depsBinaryCataloger{
		name:            "dotnet-deps-cataloger",
		considerPEFiles: false,
	}
}

// NewDotnetPortableExecutableCataloger returns a cataloger based on PE files and optionally deps.json files.
func NewDotnetPortableExecutableCataloger() pkg.Cataloger {
	return &depsBinaryCataloger{
		name:            "dotnet-portable-executable-cataloger",
		considerPEFiles: true,
	}
}

// NewDotnetPackagesLockCataloger returns a cataloger based on packages.lock.json files.
func NewDotnetPackagesLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("dotnet-packages-lock-cataloger").
		WithParserByGlobs(parseDotnetPackagesLock, "**/packages.lock.json")
}
