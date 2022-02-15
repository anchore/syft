package golang

import (
	"io"
	"runtime/debug"

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

// func parseGoBin(location source.Location, reader io.ReadCloser, opener exeOpener) (pkgs []pkg.Package, err error) {
// 	var exes []exe
// 	// it has been found that there are stdlib paths within openExe that can panic. We want to prevent this behavior
// 	// bubbling up and halting execution. For this reason we try to recover from any panic and return an error.
// 	defer func() {
// 		if r := recover(); r != nil {
// 			err = fmt.Errorf("recovered from panic while parse go binary at %q: %+v", location.RealPath, r)
// 		}
// 	}()

// 	// Identify if bin was compiled by go
// 	exes, err = opener(reader)
// 	if err != nil {
// 		return pkgs, err
// 	}

// 	for _, x := range exes {
// 		goVersion, mod := findVers(x)
// 		pkgs = append(pkgs, buildGoPkgInfo(location, mod, goVersion, x.ArchName())...)
// 	}
// 	return pkgs, err
// }

func buildGoPkgInfo(location source.Location, mod *debug.BuildInfo, goVersion, arch string) []pkg.Package {
	pkgsSlice := make([]pkg.Package, 0)

	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}

		pkgsSlice = append(pkgsSlice, newGoBinaryPackage(dep.Path, dep.Version, dep.Sum, goVersion, arch, location))
	}
	return pkgsSlice
}
