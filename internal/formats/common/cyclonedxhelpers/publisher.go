package cyclonedxhelpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func Publisher(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Maintainer
		case pkg.RpmdbMetadata:
			return metadata.Vendor
		case pkg.DpkgMetadata:
			return metadata.Maintainer
		}
	}
	return ""
}
