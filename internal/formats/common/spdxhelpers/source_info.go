package spdxhelpers

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func SourceInfo(p pkg.Package) string {
	answer := ""
	switch p.Type {
	case pkg.AlpmPkg:
		answer = "aquired package info from ALPM DB"
	case pkg.RpmPkg:
		answer = "acquired package info from RPM DB"
	case pkg.ApkPkg:
		answer = "acquired package info from APK DB"
	case pkg.DartPubPkg:
		answer = "acquired package info from pubspec manifest"
	case pkg.DebPkg:
		answer = "acquired package info from DPKG DB"
	case pkg.DotnetPkg:
		answer = "acquired package info from dotnet project assets file"
	case pkg.NpmPkg:
		answer = "acquired package info from installed node module manifest file"
	case pkg.PythonPkg:
		answer = "acquired package info from installed python package manifest file"
	case pkg.JavaPkg, pkg.JenkinsPluginPkg:
		answer = "acquired package info from installed java archive"
	case pkg.GemPkg:
		answer = "acquired package info from installed gem metadata file"
	case pkg.GoModulePkg:
		answer = "acquired package info from go module information"
	case pkg.RustPkg:
		answer = "acquired package info from rust cargo manifest"
	case pkg.PhpComposerPkg:
		answer = "acquired package info from PHP composer manifest"
	default:
		answer = "acquired package info from the following paths"
	}
	var paths []string
	for _, l := range p.Locations.ToSlice() {
		paths = append(paths, l.RealPath)
	}

	return answer + ": " + strings.Join(paths, ", ")
}
