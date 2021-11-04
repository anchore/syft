package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Description(p *pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkMetadata:
			return metadata.Description
		case pkg.NpmPackageJSONMetadata:
			return metadata.Description
		}
	}
	return ""
}

func packageExists(p *pkg.Package) bool {
	return p != nil
}

func hasMetadata(p *pkg.Package) bool {
	return packageExists(p) && p.Metadata != nil
}
