package julia

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newJuliaPackage(name, version string, m pkg.JuliaManifestEntry, location file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      juliaPackageURL(name, version, m.UUID),
		Locations: file.NewLocationSet(location),
		Type:      pkg.JuliaPkg,
		Language:  pkg.Julia,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func juliaPackageURL(name, version, uuid string) string {
	var qualifiers packageurl.Qualifiers
	if uuid != "" {
		qualifiers = packageurl.QualifiersFromMap(map[string]string{
			"uuid": uuid,
		})
	}

	return packageurl.NewPackageURL(
		packageurl.TypeJulia,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
