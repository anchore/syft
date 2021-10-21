package spdxhelpers

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

func Originator(p *pkg.Package) string {
	switch metadata := p.Metadata.(type) {
	case pkg.ApkMetadata:
		return metadata.Maintainer
	case pkg.NpmPackageJSONMetadata:
		return metadata.Author
	case pkg.PythonPackageMetadata:
		author := metadata.Author
		if author == "" {
			return metadata.AuthorEmail
		}
		if metadata.AuthorEmail != "" {
			author += fmt.Sprintf(" <%s>", metadata.AuthorEmail)
		}
		return author
	case pkg.GemMetadata:
		if len(metadata.Authors) > 0 {
			return metadata.Authors[0]
		}
		return ""
	case pkg.RpmdbMetadata:
		return metadata.Vendor
	case pkg.DpkgMetadata:
		return metadata.Maintainer
	default:
		return ""
	}
}
