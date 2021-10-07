package golang

import (
	"bufio"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	packageIdentifier = "dep"
	replaceIdentifier = "=>"
)

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
	scanner := bufio.NewScanner(strings.NewReader(mod))

	// filter mod dependencies: [dep, name, version, sha]
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch fields[0] {
		case packageIdentifier:
			pkgsSlice = append(pkgsSlice, pkg.Package{
				Name:     fields[1],
				Version:  fields[2],
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
				Locations: []source.Location{
					{
						RealPath: path,
					},
				},
			})
		case replaceIdentifier:
			pkg := &pkgsSlice[len(pkgsSlice)-1]
			pkg.Name = fields[1]
			pkg.Version = fields[2]
		}
	}

	return pkgsSlice
}
