package swift

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newSwiftPackageManagerPackage(name, version, sourceURL, revision string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      swiftPackageManagerPackageURL(name, version, sourceURL),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.SwiftPkg,
		Language:  pkg.Swift,
		Metadata: pkg.SwiftPackageManagerResolvedEntry{
			Revision: revision,
		},
	}

	p.SetID()

	return p
}

func newCocoaPodsPackage(name, version, hash string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      cocoaPodsPackageURL(name, version),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.CocoapodsPkg,
		Language:  pkg.Swift,
		Metadata: pkg.CocoaPodfileLockEntry{
			Checksum: hash,
		},
	}

	p.SetID()

	return p
}

func cocoaPodsPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

func swiftPackageManagerPackageURL(name, version, sourceURL string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeSwift,
		swiftNamespaceFromSourceURL(sourceURL, name),
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

// swiftNamespaceFromSourceURL derives the purl namespace (e.g.
// "github.com/apple") from a Swift Package.resolved source URL like
// "https://github.com/apple/swift-nio-ssl.git".
//
// Two bits of cleanup are needed compared with the previous
// strings.Replace(sourceURL, "https://", "", 1) behaviour:
//
//  1. Strip the ".git" suffix. Swift Package.resolved always carries the
//     repository URL with a trailing ".git", but the purl spec uses the
//     plain web path.
//  2. Drop the trailing /<name> segment. The previous code left the repo
//     name in the namespace and then appended the package name again, so
//     the emitted purl looked like
//     pkg:swift/github.com/apple/swift-nio-ssl.git/swift-nio-ssl@2.0.0
//     which Grype cannot match against NVD. The expected form is
//     pkg:swift/github.com/apple/swift-nio-ssl@2.0.0
//     which is also what cdxgen emits. See anchore/syft#3961.
func swiftNamespaceFromSourceURL(sourceURL, name string) string {
	ns := sourceURL
	for _, prefix := range []string{"https://", "http://", "git+ssh://", "ssh://"} {
		ns = strings.TrimPrefix(ns, prefix)
	}
	ns = strings.TrimSuffix(ns, ".git")
	if name != "" {
		if trimmed := strings.TrimSuffix(ns, "/"+name); trimmed != ns {
			ns = trimmed
		}
	}
	return ns
}
