package dotnet

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDotnetDepsBinaryCataloger returns a cataloger based on PE and deps.json file contents.
func NewDotnetDepsBinaryCataloger(config CatalogerConfig) pkg.Cataloger {
	return &depsBinaryCataloger{
		config: config,
	}
}

// NewDotnetDepsCataloger returns a cataloger based on deps.json file contents.
//
// Deprecated: use NewDotnetDepsBinaryCataloger instead which combines the PE and deps.json data which yields more accurate results (will be removed in syft v2.0).
func NewDotnetDepsCataloger() pkg.Cataloger {
	return &depsCataloger{}
}

// NewDotnetPortableExecutableCataloger returns a cataloger based on PE file contents.
//
// Deprecated: use NewDotnetDepsBinaryCataloger instead which combines the PE and deps.json data which yields more accurate results (will be removed in syft v2.0).
func NewDotnetPortableExecutableCataloger() pkg.Cataloger {
	return &binaryCataloger{}
}

// NewDotnetPackagesLockCataloger returns a cataloger based on packages.lock.json files.
func NewDotnetPackagesLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("dotnet-packages-lock-cataloger").
		WithParserByGlobs(parseDotnetPackagesLock, "**/packages.lock.json")
}
