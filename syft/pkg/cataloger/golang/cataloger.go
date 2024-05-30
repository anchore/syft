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
)

// NewGoModuleFileCataloger returns a new cataloger object that searches within go.mod files.
func NewGoModuleFileCataloger(opts CatalogerConfig) pkg.Cataloger {
	c := goModCataloger{
		licenses: newGoLicenses(modFileCatalogerName, opts),
	}

	return generic.NewCataloger(modFileCatalogerName).
		WithParserByGlobs(c.parseGoModFile, "**/go.mod")
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
