package dart

import (
	"context"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

func newPubspecLockPackage(name string, raw pubspecLockPackage, locations ...file.Location) pkg.Package {
	metadata := pkg.DartPubspecLockEntry{
		Name:      name,
		Version:   raw.Version,
		HostedURL: raw.getHostedURL(),
		VcsURL:    raw.getVcsURL(),
	}

	p := pkg.Package{
		Name:      name,
		Version:   raw.Version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURLFromPubspecLock(metadata),
		Language:  pkg.Dart,
		Type:      pkg.DartPubPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func newPubspecPackage(ctx context.Context, resolver file.Resolver, raw pubspecPackage, locations ...file.Location) pkg.Package {
	var env *pkg.DartPubspecEnvironment
	if raw.Environment.SDK != "" || raw.Environment.Flutter != "" {
		// this is required only after pubspec v2, but might have been optional before this
		env = &pkg.DartPubspecEnvironment{
			SDK:     raw.Environment.SDK,
			Flutter: raw.Environment.Flutter,
		}
	}
	p := pkg.Package{
		Name:      raw.Name,
		Version:   raw.Version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURLFromPubspec(raw.Name, raw.Version),
		Language:  pkg.Dart,
		Type:      pkg.DartPubPkg,
		Metadata: pkg.DartPubspec{
			Homepage:          raw.Homepage,
			Repository:        raw.Repository,
			Documentation:     raw.Documentation,
			PublishTo:         raw.PublishTo,
			Environment:       env,
			Platforms:         raw.Platforms,
			IgnoredAdvisories: raw.IgnoredAdvisories,
		},
	}

	p.SetID()

	p = licenses.RelativeToPackage(ctx, resolver, p)

	return p
}

func packageURLFromPubspecLock(m pkg.DartPubspecLockEntry) string {
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

func packageURLFromPubspec(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypePub,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
