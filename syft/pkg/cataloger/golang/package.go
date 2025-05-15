package golang

import (
	"runtime/debug"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func (c *goBinaryCataloger) newGoBinaryPackage(dep *debug.Module, m pkg.GolangBinaryBuildinfoEntry, licenses []pkg.License, locations ...file.Location) pkg.Package {
	if dep.Replace != nil {
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
		Name:      dep.Path,
		Version:   version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(dep.Path, version),
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

	fields := strings.Split(moduleName, "/")
	if len(fields) == 0 {
		return ""
	}

	namespace := ""
	name := ""
	// The subpath is used to point to a subpath inside a package (e.g. pkg:golang/google.golang.org/genproto#googleapis/api/annotations)
	subpath := ""

	switch len(fields) {
	case 1:
		name = fields[0]
	case 2:
		name = fields[1]
		namespace = fields[0]
	default:
		name = fields[2]
		namespace = strings.Join(fields[0:2], "/")
		subpath = strings.Join(fields[3:], "/")
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGolang,
		namespace,
		name,
		moduleVersion,
		nil,
		subpath,
	).ToString()
}
