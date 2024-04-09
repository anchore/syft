package dotnet

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newDotnetDepsPackage(nameVersion string, lib dotnetDepsLibrary, locations ...file.Location) *pkg.Package {
	name, version := extractNameAndVersion(nameVersion)

	m := pkg.DotnetDepsEntry{
		Name:     name,
		Version:  version,
		Path:     lib.Path,
		Sha512:   lib.Sha512,
		HashPath: lib.HashPath,
	}

	p := &pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(m),
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func getDepsJSONFilePrefix(p string) string {
	r := regexp.MustCompile(`([^\\\/]+)\.deps\.json$`)
	match := r.FindStringSubmatch(p)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func extractNameAndVersion(nameVersion string) (name, version string) {
	fields := strings.Split(nameVersion, "/")
	name = fields[0]
	version = fields[1]
	return
}

func createNameAndVersion(name, version string) (nameVersion string) {
	nameVersion = fmt.Sprintf("%s/%s", name, version)
	return
}

func packageURL(m pkg.DotnetDepsEntry) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		// This originally was packageurl.TypeDotnet, but this isn't a valid PURL type, according to:
		// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
		// Some history:
		//   https://github.com/anchore/packageurl-go/pull/8 added the type to Anchore's fork
		//   due to this PR: https://github.com/anchore/syft/pull/951
		// There were questions about "dotnet" being the right purlType at the time, but it was
		// acknowledged that scanning a dotnet file does not necessarily mean the packages found
		// are nuget packages and so the alternate type was added. Since this is still an invalid
		// PURL type, however, we will use TypeNuget and revisit at such time there is a better
		// official PURL type available.
		packageurl.TypeNuget,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
