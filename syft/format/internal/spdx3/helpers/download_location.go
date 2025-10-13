package helpers

import (
	"strings"

	urilib "github.com/spdx/gordf/uri"

	"github.com/anchore/syft/syft/pkg"
)

const NONE = "NONE"
const NOASSERTION = "NOASSERTION"

func DownloadLocation(p pkg.Package) string {
	// 3.7: Package Download Location
	// Cardinality: mandatory, one
	// NONE if there is no download location whatsoever.
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	var location string
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			location = metadata.URL
		case pkg.NpmPackage:
			location = metadata.URL
		case pkg.NpmPackageLockEntry:
			location = metadata.Resolved
		case pkg.PhpComposerLockEntry:
			location = metadata.Dist.URL
		case pkg.PhpComposerInstalledEntry:
			location = metadata.Dist.URL
		case pkg.OpamPackage:
			location = metadata.URL
		}
	}
	return URIValue(location)
}

func isURIValid(uri string) bool {
	_, err := urilib.NewURIRef(uri)
	return err == nil
}

func URIValue(uri string) string {
	if strings.ToLower(uri) != "none" {
		if isURIValid(uri) {
			return uri
		}
		return NOASSERTION
	}
	return NONE
}
