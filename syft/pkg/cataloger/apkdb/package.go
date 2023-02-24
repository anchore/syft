package apkdb

import (
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var (
	prefixes = []string{"py-", "py2-", "py3-", "ruby-"}
)

func newPackage(d pkg.ApkMetadata, release *linux.Release, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Locations:    source.NewLocationSet(locations...),
		Licenses:     strings.Split(d.License, " "),
		PURL:         packageURL(d, release),
		Type:         pkg.ApkPkg,
		MetadataType: pkg.ApkMetadataType,
		Metadata:     d,
	}

	p.SetID()

	return p
}

func generateUpstream(m pkg.ApkMetadata) string {
	if m.OriginPackage != "" && m.OriginPackage != m.Package {
		return m.OriginPackage
	}

	for _, p := range prefixes {
		if strings.HasPrefix(m.Package, p) {
			return strings.TrimPrefix(m.Package, p)
		}
	}

	pattern := regexp.MustCompile(`^(?P<upstream>[\w-]+?)\-?\d[\d\.]*$`)
	groups := internal.MatchNamedCaptureGroups(pattern, m.Package)

	upstream, ok := groups["upstream"]
	if ok {
		return upstream
	}

	return m.Package
}

// packageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.ApkMetadata, distro *linux.Release) string {
	if distro == nil || distro.ID != "alpine" {
		// note: there is no namespace variation (like with debian ID_LIKE for ubuntu ID, for example)
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	if m.OriginPackage != "" {
		qualifiers[pkg.PURLQualifierUpstream] = generateUpstream(m)
	}

	return packageurl.NewPackageURL(
		packageurl.TypeAlpine,
		"alpine",
		m.Package,
		m.Version,
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
