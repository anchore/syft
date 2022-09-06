package cyclonedxhelpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func encodePublisher(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Maintainer
		case pkg.RpmMetadata:
			return metadata.Vendor
		case pkg.DpkgMetadata:
			return metadata.Maintainer
		}
	}
	return ""
}

func decodePublisher(publisher string, metadata interface{}) {
	switch meta := metadata.(type) {
	case *pkg.ApkMetadata:
		meta.Maintainer = publisher
	case *pkg.RpmMetadata:
		meta.Vendor = publisher
	case *pkg.DpkgMetadata:
		meta.Maintainer = publisher
	}
}
