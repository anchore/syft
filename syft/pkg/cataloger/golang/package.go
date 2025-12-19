package golang

import (
	"runtime/debug"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func (c *goBinaryCataloger) newGoBinaryPackage(dep *debug.Module, m pkg.GolangBinaryBuildinfoEntry, licenses []pkg.License, locations ...file.Location) pkg.Package {
	// Similar to syft/pkg/cataloger/golang/parse_go_mod.go logic - use original path for relative replacements
	finalPath := dep.Path
	if dep.Replace != nil {
		if strings.HasPrefix(dep.Replace.Path, ".") || strings.HasPrefix(dep.Replace.Path, "/") {
			finalPath = dep.Path
		} else {
			finalPath = dep.Replace.Path
		}
		dep = dep.Replace
	}

	version := dep.Version
	if version == devel {
		// this is a special case for the "devel" version, which is used when the module is built from source
		// and there is no vcs tag info available. In this case, we remove the placeholder to indicate
		// we don't know the version.
		version = ""
	}

	p := pkg.Package{
		Name:      finalPath,
		Version:   version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(finalPath, version),
		Language:  pkg.Go,
		Type:      pkg.GoModulePkg,
		Locations: file.NewLocationSet(locations...),
		Metadata:  m,
	}

	p.SetID()

	return p
}

func newBinaryMetadata(dep *debug.Module, mainModule, goVersion, architecture string, buildSettings pkg.KeyValues, cryptoSettings, experiments []string) pkg.GolangBinaryBuildinfoEntry {
	if dep.Replace != nil {
		dep = dep.Replace
	}

	return pkg.GolangBinaryBuildinfoEntry{
		GoCompiledVersion: goVersion,
		H1Digest:          dep.Sum,
		Architecture:      architecture,
		BuildSettings:     buildSettings,
		MainModule:        mainModule,
		GoCryptoSettings:  cryptoSettings,
		GoExperiments:     experiments,
	}
}

func packageURL(moduleName, moduleVersion string) string {
	// source: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#golang
	// note: "The version is often empty when a commit is not specified and should be the commit in most cases when available."
	if moduleName == "" {
		return ""
	}

	namespace := ""
	name := moduleName

	// golang PURLs from _modules_ are constructed as pkg:golang/<module>@version, where
	// the full module name often includes multiple segments including `/v#`-type versions, for example:
	//  pkg:golang/github.com/cli/cli/v2@2.63.0
	// see: https://github.com/package-url/purl-spec/issues/63
	// and: https://github.com/package-url/purl-spec/blob/main/types-doc/golang-definition.md#subpath-definition
	// by setting the namespace this way, it does not escape the slashes:
	lastSlash := strings.LastIndex(moduleName, "/")
	if lastSlash > 0 && lastSlash < len(moduleName)-1 {
		name = moduleName[lastSlash+1:]
		namespace = moduleName[0:lastSlash]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGolang,
		namespace,
		name,
		moduleVersion,
		nil,
		"", // subpath is used to reference a specific _package_ within the module
	).ToString()
}
