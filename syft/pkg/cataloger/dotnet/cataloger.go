/*
Package dotnet provides a concrete Cataloger implementation relating to packages within the C#/.NET language/runtime ecosystem.
*/
package dotnet

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	dotnetDepsCatalogerName               = "dotnet-deps-cataloger"
	dotnetPortableExecutableCatalogerName = "dotnet-portable-executable-cataloger"
)

// NewDotnetDepsCataloger returns a new Dotnet cataloger object base on deps json files.
func NewDotnetDepsCataloger(opts CatalogerConfig) pkg.Cataloger {
	c := dotnetDepsCataloger{
		licenses: newNugetLicenses(opts),
	}
	return generic.NewCataloger(dotnetDepsCatalogerName).
		WithParserByGlobs(c.parseDotnetDeps, "**/*.deps.json")
}

// NewDotnetPortableExecutableCataloger returns a new Dotnet cataloger object base on portable executable files.
func NewDotnetPortableExecutableCataloger(opts CatalogerConfig) pkg.Cataloger {
	c := dotnetPortableExecutableCataloger{
		licenses: newNugetLicenses(opts),
	}
	return generic.NewCataloger(dotnetPortableExecutableCatalogerName).
		WithParserByGlobs(c.parseDotnetPortableExecutable, "**/*.dll", "**/*.exe")
}
