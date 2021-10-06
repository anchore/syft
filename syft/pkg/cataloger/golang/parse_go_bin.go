package golang

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

const packageIdentifier = "dep"

func parseGoBin(path string, reader io.ReadCloser) ([]pkg.Package, error) {
	pkgsSlice := make([]pkg.Package, 0)

	// Identify if bin was compiled by go
	x, err := openExe(reader)
	if err != nil {
		return pkgsSlice, err
	}

	_, mod := findVers(x)
	fields := strings.Fields(mod)

	// slice off root pacakge info
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
			})
		}
	}

	sort.SliceStable(pkgsSlice, func(i, j int) bool {
		return pkgsSlice[i].Name < pkgsSlice[j].Name
	})

	return pkgsSlice, nil
}
