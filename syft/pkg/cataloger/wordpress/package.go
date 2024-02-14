package wordpress

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newWordpressPluginPackage(name, version string, m pluginData, location file.Location) pkg.Package {
	meta := pkg.WordpressPluginEntry{
		PluginInstallDirectory: m.PluginInstallDirectory,
		Author:                 m.Author,
		AuthorURI:              m.AuthorURI,
	}

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Language:  pkg.PHP,
		Type:      pkg.WordpressPluginPkg,
		Metadata:  meta,
	}

	if len(m.Licenses) > 0 {
		p.Licenses = pkg.NewLicenseSet(pkg.NewLicense(m.Licenses[0]))
	}

	p.SetID()

	return p
}
