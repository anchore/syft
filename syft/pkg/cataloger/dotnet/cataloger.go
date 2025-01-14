/*
Package dotnet provides a concrete Cataloger implementation relating to packages within the C#/.NET language/runtime ecosystem.
*/
package dotnet

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDotnetDepsCataloger returns a new Dotnet cataloger object base on deps json files.
func NewDotnetDepsCataloger() pkg.Cataloger {
	return generic.NewCataloger("dotnet-deps-cataloger").
		WithParserByGlobs(parseDotnetDeps, "**/*.deps.json")
}

// NewDotnetPortableExecutableCataloger returns a new Dotnet cataloger object base on portable executable files.
func NewDotnetPortableExecutableCataloger() pkg.Cataloger {
	return generic.NewCataloger("dotnet-portable-executable-cataloger").
		WithParserByGlobs(parseDotnetPortableExecutable, "**/*.dll", "**/*.exe")
}

func NewDotnetPackagesLockCataloger() pkg.Cataloger {
	return generic.NewCataloger("dotnet-packages-lock-cataloger").WithParserByGlobs(parseDotnetPackagesLock, "**/packages.lock.json")
}
