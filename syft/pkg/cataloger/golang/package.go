package golang

import (
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func (c *goBinaryCataloger) newGoBinaryPackage(resolver file.Resolver, dep *debug.Module, mainModule, goVersion, architecture string, buildSettings map[string]string, cryptoSettings []string, locations ...file.Location) pkg.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}

	licenses, err := c.licenses.getLicenses(resolver, dep.Path, dep.Version)
	if err != nil {
		log.Tracef("error getting licenses for golang package: %s %v", dep.Path, err)
	}

	p := pkg.Package{
		Name:      dep.Path,
		Version:   dep.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(dep.Path, dep.Version),
		Language:  pkg.Go,
		Type:      pkg.GoModulePkg,
		Locations: file.NewLocationSet(locations...),
		Metadata: pkg.GolangBinaryBuildinfoEntry{
			GoCompiledVersion: goVersion,
			H1Digest:          dep.Sum,
			Architecture:      architecture,
			BuildSettings:     buildSettings,
			MainModule:        mainModule,
			GoCryptoSettings:  cryptoSettings,
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
