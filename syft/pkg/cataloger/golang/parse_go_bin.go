package golang

import (
	"runtime/debug"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newGoBinaryPackage(dep *debug.Module, settings map[string]string, goVersion, architecture string, location source.Location) pkg.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}

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

func getBuildSettings(settings []debug.BuildSetting) map[string]string {
	m := make(map[string]string)
	for _, s := range settings {
		m[s.Key] = s.Value
	}
	return m
}

func buildGoPkgInfo(location source.Location, mod *debug.BuildInfo) []pkg.Package {
	pkgs := make([]pkg.Package, 0)
	if mod == nil {
		return pkgs
	}

	gbs := getBuildSettings(mod.Settings)
	arch := getGOARCH(mod.Settings)
	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}

		pkgs = append(pkgs, newGoBinaryPackage(dep, gbs, mod.GoVersion, arch, location))
	}

	return pkgs
}
