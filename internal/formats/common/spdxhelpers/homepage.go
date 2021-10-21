package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Homepage(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.GemMetadata:
		return metadata.Homepage
	case pkg.NpmPackageJSONMetadata:
		return metadata.Homepage
	default:
		return ""
	}
}
