/*
Package golang provides a concrete Cataloger implementation relating to packages within the Go language ecosystem.
*/
package golang

import (
	"regexp"

	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var versionCandidateGroups = regexp.MustCompile(`(?P<version>\d+(\.\d+)?(\.\d+)?)(?P<candidate>\w*)`)

const (
	modFileCatalogerName    = "go-module-file-cataloger"
	binaryCatalogerName     = "go-module-binary-cataloger"
	sourceFileCatalogerName = "go-module-source-file-cataloger"
)

// NewGoModuleFileCataloger returns a new cataloger object that searches within go.mod files.
func NewGoModuleFileCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(modFileCatalogerName).
		WithParserByGlobs(newGoModCataloger(opts).parseGoModFile, "**/go.mod")
}

// NewGoModuleBinaryCataloger returns a new cataloger object that searches within binaries built by the go compiler.
func NewGoModuleBinaryCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(binaryCatalogerName).
		WithParserByMimeTypes(
			newGoBinaryCataloger(opts).parseGoBinary,
			mimetype.ExecutableMIMETypeSet.List()...,
		).
		WithProcessors(stdlibProcessor)
}

// NewGoModuleSourceFileCataloger returns a new cataloger object that uses the go.mod file
// to extract the module name and then searches all direct and transitive dependencies
// for the given module source tree
func NewGoModuleSourceFileCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(modFileCatalogerName).
		WithParserByGlobs(newGoModSourceCataloger(opts).parseGoModFile, "**/go.mod")
}
