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

func parseGoBin(location source.Location, reader io.ReadCloser) ([]pkg.Package, error) {
	// Identify if bin was compiled by go
	exes, err := openExe(reader)
	if err != nil {
		return nil, err
	}

	var pkgs []pkg.Package
	for _, x := range exes {
		goVersion, mod := findVers(x)
		pkgs = append(pkgs, buildGoPkgInfo(location, mod, goVersion, x.ArchName())...)
	}
	return pkgs, nil
}

func buildGoPkgInfo(location source.Location, mod, goVersion, arch string) []pkg.Package {
	pkgsSlice := make([]pkg.Package, 0)
	scanner := bufio.NewScanner(strings.NewReader(mod))

	// filter mod dependencies: [dep, name, version, sha]
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		// must have dep, name, version, sha
		if len(fields) < 4 {
			continue
		}

		if fields[0] == packageIdentifier || fields[0] == replaceIdentifier {
			pkgsSlice = append(pkgsSlice, pkg.Package{
				Name:     fields[1],
				Version:  fields[2],
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
				Locations: []source.Location{
					location,
				},
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					GoCompiledVersion: goVersion,
					H1Digest:          fields[3],
					Architecture:      arch,
				},
			})
		}
	}

	return pkgsSlice
}
