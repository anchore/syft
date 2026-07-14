package helpers

import (
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
)

// Homepage returns the upstream project homepage for a package, derived from whatever URL/homepage
// field the package metadata provides. This populates the SPDX PackageHomePage field.
//
// ruby and npm are handled here because CycloneDX classifies them as distinct website/distribution
// references rather than plain homepages; every other ecosystem comes from the shared internal.Homepage
// source that the CycloneDX website encoder also uses.
func Homepage(p pkg.Package) string {
	if !hasMetadata(p) {
		return ""
	}

	switch metadata := p.Metadata.(type) {
	case pkg.RubyGemspec:
		return metadata.Homepage
	case pkg.NpmPackage:
		return metadata.Homepage
	}
	return internal.Homepage(p)
}
