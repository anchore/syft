package dotnet

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newDotnetDepsPackage(nameVersion string, lib dotnetDepsLibrary, locations ...source.Location) *pkg.Package {
	if lib.Type != "package" {
		return nil
	}

	fields := strings.Split(nameVersion, "/")
	name := fields[0]
	version := fields[1]

	m := pkg.DotnetDepsMetadata{
		Name:     name,
		Version:  version,
		Path:     lib.Path,
		Sha512:   lib.Sha512,
		HashPath: lib.HashPath,
	}

	p := &pkg.Package{
		Name:         name,
		Version:      version,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(m),
		Language:     pkg.Dotnet,
		Type:         pkg.DotnetPkg,
		MetadataType: pkg.DotnetDepsMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.DotnetDepsMetadata) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeDotnet,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
