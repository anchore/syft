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

func newGoBinaryPackage(name, version, h1Digest, goVersion, architecture string, location source.Location) pkg.Package {
	p := pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Locations: []source.Location{
			location,
		},
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goVersion,
			H1Digest:          h1Digest,
			Architecture:      architecture,
		},
	}

	p.SetID()

	return p
}

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

		// must have dep, name, version
		if len(fields) < 3 {
			continue
		}

		name := fields[1]
		version := fields[2]
		h1Digest := ""
		// if dep is *not* vendored, it'll also have h1digest
		if len(fields) >= 4 {
			h1Digest = fields[3]
		}

		if fields[0] == packageIdentifier {
			pkgsSlice = append(pkgsSlice, newGoBinaryPackage(name, version, h1Digest, goVersion, arch, location))
		}
		if fields[0] == replaceIdentifier {
			// replace the previous entry in the package slice
			pkgsSlice[len(pkgsSlice)-1] = newGoBinaryPackage(name, version, h1Digest, goVersion, arch, location)
		}
	}
	return pkgsSlice
}
