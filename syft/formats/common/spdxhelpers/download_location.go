package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

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

	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return NoneIfEmpty(metadata.URL)
		case pkg.NpmPackageJSONMetadata:
			return NoneIfEmpty(metadata.URL)
		}
	}
	return NOASSERTION
}
