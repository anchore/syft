package helpers

import (
	"github.com/anchore/syft/syft/pkg"
	urilib "github.com/spdx/gordf/uri"
)

const NONE = "NONE"
const NOASSERTION = "NOASSERTION"

func isUriValid(uri string) bool {
	_, err := urilib.NewURIRef(uri)
	return err == nil
}

func checkUri(uri string) string {
	if NoneIfEmpty(uri) != NONE {
		if isUriValid(uri) {
			return uri
		} else {
			return NOASSERTION
		}
	}
	return NONE
}

func DownloadLocation(p pkg.Package) string {
	// 3.7: Package Download Location
	// Cardinality: mandatory, one
	// NONE if there is no download location whatsoever.
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			return checkUri(metadata.URL)
		case pkg.NpmPackage:
			return checkUri(metadata.URL)
		case pkg.NpmPackageLockEntry:
			return checkUri(metadata.Resolved)
		case pkg.PhpComposerLockEntry:
			return checkUri(metadata.Dist.URL)
		case pkg.PhpComposerInstalledEntry:
			return checkUri(metadata.Dist.URL)
		case pkg.OpamPackage:
			return checkUri(metadata.URL)
		}
	}
	return NOASSERTION
}
