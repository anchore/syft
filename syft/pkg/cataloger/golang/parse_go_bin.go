package golang

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	packageIdentifier = "dep"
	replaceIdentifier = "=>"
)

type exeOpener func(file io.ReadCloser) ([]exe, error)

func parseGoBin(location source.Location, reader io.ReadCloser, opener exeOpener) (pkgs []pkg.Package, err error) {
	var exes []exe
	// it has been found that there are stdlib paths within openExe that can panic. We want to prevent this behavior
	// bubbling up and halting execution. For this reason we try to recover from any panic and return an error.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic while parse go binary at %q: %+v", location.RealPath, r)
		}
	}()

	// Identify if bin was compiled by go
	exes, err = opener(reader)
	if err != nil {
		return pkgs, err
	}

	for _, x := range exes {
		goVersion, mod := findVers(x)
		pkgs = append(pkgs, buildGoPkgInfo(location, mod, goVersion, x.ArchName())...)
	}
	return pkgs, err
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
