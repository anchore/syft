package cyclonedxhelpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func Author(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.NpmPackageJSONMetadata:
			return metadata.Author
		case pkg.PythonPackageMetadata:
			author := metadata.Author
			if author == "" {
				return metadata.AuthorEmail
			}
			return author
		case pkg.GemMetadata:
			if len(metadata.Authors) > 0 {
				return metadata.Authors[0]
			}
			return ""
		}
	}
	return ""
}
