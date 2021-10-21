package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Description(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.Description
	case pkg.NpmPackageJSONMetadata:
		return metadata.Description
	default:
		return ""
	}
}
