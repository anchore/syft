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
	modFileCatalogerName = "go-module-file-cataloger"
	binaryCatalogerName  = "go-module-binary-cataloger"
	sourceCatalogerName  = "go-source-cataloger"
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
		WithResolvingProcessors(stdlibProcessor)
}

// TODO: not generic anymore we want custom so it's called ONCE and returns all knowledge of **/go.mod
// We only want to scan once here
// edge cases here are:
// They just gave me root of a file system with multiple go.mod
// is that part of this PR?
// syft config source.base-path <-- Check that this works when this is set
// resolver should handle the src config stuff
// location.Reference().RealPath <--- absolute path; ignore src config
// location.RealPath <-- normalized value for src config
func NewGoSourceCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(sourceCatalogerName).
		WithParserByGlobs(newGoSourceCataloger(opts).parseGoSourceEntry, "**/go.mod")
}
