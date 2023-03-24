package nixstore

import (
	"fmt"
	"regexp"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/pkg"
)

var (
	errEndOfPackages = fmt.Errorf("no more packages to read")
	sourceRegexp     = regexp.MustCompile(`/nix/store/[^-]*-(?P<name>[^-]*)-(?P<version>[^-/]*).*/`)
)

func newNixStorePackage(d pkg.NixStoreMetadata) pkg.Package {
	return pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Type:         pkg.NixStorePkg,
		MetadataType: pkg.NixStoreMetadataType,
		Metadata:     d,
	}
}

func extractNameAndVersion(source string) (string, string) {
	// special handling for the Source field since it has formatted data
	match := internal.MatchNamedCaptureGroups(sourceRegexp, source)
	return match["name"], match["version"]
}
