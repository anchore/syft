package wordpress

import (
	"context"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newWordpressPluginPackage(ctx context.Context, name, version string, m pluginData, location file.Location) pkg.Package {
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
		licenseCandidates := make([]pkg.LicenseCandidate, 0)
		for _, l := range m.Licenses {
			licenseCandidates = append(licenseCandidates, pkg.LicenseCandidate{Value: l, Location: location})
		}
		p.Licenses = pkg.NewLicenseBuilder().WithCandidates(licenseCandidates...).Build(ctx)
	}

	p.SetID()

	return p
}
