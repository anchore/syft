package golang

import (
	"runtime/debug"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newGoBinaryPackage(dep *debug.Module, settings []pkg.GolangBuildSetting, goVersion, architecture string, location source.Location) pkg.Package {
	p := pkg.Package{
		Name:     dep.Path,
		Version:  dep.Version,
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Locations: []source.Location{
			location,
		},
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goVersion,
			H1Digest:          dep.Sum,
			Architecture:      architecture,
			BuildSettings:     settings,
		},
	}

	p.SetID()

	return p
}

func getGOARCH(settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key == "GOARCH" {
			return s.Value
		}
	}

	return ""
}

func getBuildSettings(settings []debug.BuildSetting) (gbs []pkg.GolangBuildSetting) {
	for _, s := range settings {
		b := pkg.GolangBuildSetting{
			Key:   s.Key,
			Value: s.Value,
		}
		gbs = append(gbs, b)
	}
	return
}

func buildGoPkgInfo(location source.Location, mod *debug.BuildInfo) []pkg.Package {
	pkgsSlice := make([]pkg.Package, 0)

	if mod == nil {
		return pkgsSlice
	}

	gbs := getBuildSettings(mod.Settings)
	arch := getGOARCH(mod.Settings)
	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}

		pkgsSlice = append(pkgsSlice, newGoBinaryPackage(dep, gbs, mod.GoVersion, arch, location))
	}
	return pkgsSlice
}
