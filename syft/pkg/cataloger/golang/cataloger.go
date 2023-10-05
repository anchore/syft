/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewGoModFileCataloger returns a new Go module cataloger object.
func NewGoModFileCataloger(opts GoCatalogerOpts) pkg.Cataloger {
	c := goModCataloger{
		licenses: newGoLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("go-mod-file-cataloger").
			WithParserByGlobs(c.parseGoModFile, "**/go.mod"),
	}
}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
func NewGoModuleBinaryCataloger(opts GoCatalogerOpts) pkg.Cataloger {
	c := goBinaryCataloger{
		licenses: newGoLicenses(opts),
	}
	return &progressingCataloger{
		progress: c.licenses.progress,
		cataloger: generic.NewCataloger("go-module-binary-cataloger").
			WithParserByMimeTypes(c.parseGoBinary, internal.ExecutableMIMETypeSet.List()...),
	}
}

type progressingCataloger struct {
	progress  *monitor.CatalogerTask
	cataloger *generic.Cataloger
}

func (p *progressingCataloger) Name() string {
	return p.cataloger.Name()
}

func (p *progressingCataloger) Catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	defer p.progress.SetCompleted()
	pkgs, relationships, err := p.cataloger.Catalog(resolver)
	goCompilerPkgs := []pkg.Package{}
	totalLocations := file.NewLocationSet()
	for _, goPkg := range pkgs {
		// go binary packages should only contain a single location
		for _, location := range goPkg.Locations.ToSlice() {
			if !totalLocations.Contains(location) {
				if mValue, ok := goPkg.Metadata.(pkg.GolangBinMetadata); ok {
					stdLibPkg := newGoStdLib(mValue.GoCompiledVersion, goPkg.Locations)
					if stdLibPkg != nil {
						goCompilerPkgs = append(goCompilerPkgs, *stdLibPkg)
					}
					totalLocations.Add(location)
				}
			}
		}
	}
	pkgs = append(pkgs, goCompilerPkgs...)
	return pkgs, relationships, err
}
func newGoStdLib(version string, location file.LocationSet) *pkg.Package {
	// for matching we need to strip the go prefix
	// this can be preserved for metadata purposes
	matchVersion := strings.TrimPrefix(version, "go")
	cpes := make([]cpe.CPE, 0)
	compilerCPE, err := cpe.New(fmt.Sprintf("cpe:2.3:a:golang:go:%s:-:*:*:*:*:*:*", matchVersion))
	if err != nil {
		log.Warn("could not build cpe for given compiler version: %s", version)
		return nil
	}

	cpes = append(cpes, compilerCPE)
	goCompilerPkg := &pkg.Package{
		Name:         "Golang Standard Library",
		Version:      version,
		PURL:         packageURL("stdlib", matchVersion),
		CPEs:         cpes,
		Locations:    location,
		Language:     pkg.Go,
		Type:         pkg.GoModulePkg,
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: version,
		},
	}
	goCompilerPkg.SetID()

	return goCompilerPkg
}
