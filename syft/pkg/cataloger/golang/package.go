package golang

import (
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newGoBinaryPackage(dep *debug.Module, mainModule, goVersion, architecture string, buildSettings map[string]string, locations ...source.Location) pkg.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}

	p := pkg.Package{
		Name:         dep.Path,
		Version:      dep.Version,
		PURL:         packageURL(dep.Path, dep.Version),
		Language:     pkg.Go,
		Type:         pkg.GoModulePkg,
		Locations:    source.NewLocationSet(locations...),
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goVersion,
			H1Digest:          dep.Sum,
			Architecture:      architecture,
			BuildSettings:     buildSettings,
			MainModule:        mainModule,
		},
	}

	p.SetID()

	return p
}

func packageURL(moduleName, moduleVersion string) string {
	// source: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#golang
	// note: "The version is often empty when a commit is not specified and should be the commit in most cases when available."

	re := regexp.MustCompile(`(/)[^/]*$`)
	fields := re.Split(moduleName, -1)
	if len(fields) == 0 {
		return ""
	}
	namespace := fields[0]
	name := strings.TrimPrefix(strings.TrimPrefix(moduleName, namespace), "/")

	if name == "" {
		// this is a "short" url (with no namespace)
		name = namespace
		namespace = ""
	}

	// The subpath is used to point to a subpath inside a package (e.g. pkg:golang/google.golang.org/genproto#googleapis/api/annotations)
	subpath := "" // TODO: not implemented

	return packageurl.NewPackageURL(
		packageurl.TypeGolang,
		namespace,
		name,
		moduleVersion,
		nil,
		subpath,
	).ToString()
}
