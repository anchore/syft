package dart

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPubspecLockPackage(name string, raw pubspecLockPackage, locations ...source.Location) pkg.Package {
	metadata := pkg.DartPubMetadata{
		Name:      name,
		Version:   raw.Version,
		HostedURL: raw.getHostedURL(),
		VcsURL:    raw.getVcsURL(),
	}

	p := pkg.Package{
		Name:         name,
		Version:      raw.Version,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(metadata),
		Language:     pkg.Dart,
		Type:         pkg.DartPubPkg,
		MetadataType: pkg.DartPubMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.DartPubMetadata) string {
	var qualifiers packageurl.Qualifiers

	if m.HostedURL != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "hosted_url",
			Value: m.HostedURL,
		})
	} else if m.VcsURL != "" { // Default to using Hosted if somehow both are provided
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "vcs_url",
			Value: m.VcsURL,
		})
	}

	return packageurl.NewPackageURL(
		packageurl.TypePub,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
