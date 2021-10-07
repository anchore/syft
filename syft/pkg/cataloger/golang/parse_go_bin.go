package golang

import (
	"io"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const packageIdentifier = "dep"

func parseGoBin(path string, reader io.ReadCloser) ([]pkg.Package, error) {
	// Identify if bin was compiled by go
	x, err := openExe(reader)
	if err != nil {
		return nil, err
	}

	_, mod := findVers(x)

	pkgs := buildGoPkgInfo(path, mod)

	return pkgs, nil
}

func buildGoPkgInfo(path, mod string) []pkg.Package {
	pkgsSlice := make([]pkg.Package, 0)
	fields := strings.Fields(mod)

	// slice off root package info
	var separator int
	for x, field := range fields {
		if field == packageIdentifier {
			separator = x - 1
			break
		}
	}

	fields = fields[separator:]

	// filter deps: [dep, name, version, sha]
	for x, field := range fields {
		if field == packageIdentifier {
			pkgsSlice = append(pkgsSlice, pkg.Package{
				Name:     fields[x+1],
				Version:  fields[x+2],
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
				Locations: []source.Location{
					{
						RealPath: path,
					},
				},
			})
		}
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})

	return pkgsSlice
}
