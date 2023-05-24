package cpp

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newConanfilePackage(m pkg.ConanMetadata, locations ...file.Location) *pkg.Package {
	fields := strings.Split(strings.TrimSpace(m.Ref), "/")
	if len(fields) < 2 {
		return nil
	}

	pkgName, pkgVersion := fields[0], fields[1]

	if pkgName == "" || pkgVersion == "" {
		return nil
	}

	p := pkg.Package{
		Name:         pkgName,
		Version:      pkgVersion,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(pkgName, pkgVersion),
		Language:     pkg.CPP,
		Type:         pkg.ConanPkg,
		MetadataType: pkg.ConanMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return &p
}

func newConanlockPackage(m pkg.ConanLockMetadata, locations ...file.Location) *pkg.Package {
	fields := strings.Split(strings.Split(m.Ref, "@")[0], "/")
	if len(fields) < 2 {
		return nil
	}

	pkgName, pkgVersion := fields[0], fields[1]

	if pkgName == "" || pkgVersion == "" {
		return nil
	}

	p := pkg.Package{
		Name:         pkgName,
		Version:      pkgVersion,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(pkgName, pkgVersion),
		Language:     pkg.CPP,
		Type:         pkg.ConanPkg,
		MetadataType: pkg.ConanLockMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return &p
}

func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		"",
		name,
		version,
		nil, // TODO: no qualifiers (...yet)
		"",
	).ToString()
}
