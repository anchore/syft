package cyclonedxhelpers

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func encodeAuthor(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.NpmPackageJSONMetadata:
			return metadata.Author
		case pkg.PythonPackageMetadata:
			author := metadata.Author
			if metadata.AuthorEmail != "" {
				if author == "" {
					return metadata.AuthorEmail
				}
				author += fmt.Sprintf(" <%s>", metadata.AuthorEmail)
			}
			return author
		case pkg.GemMetadata:
			if len(metadata.Authors) > 0 {
				return strings.Join(metadata.Authors, ",")
			}
			return ""
		}
	}
	return ""
}

func decodeAuthor(author string, metadata interface{}) {
	switch meta := metadata.(type) {
	case *pkg.NpmPackageJSONMetadata:
		meta.Author = author
	case *pkg.PythonPackageMetadata:
		parts := strings.SplitN(author, " <", 2)
		meta.Author = parts[0]
		if len(parts) > 1 {
			meta.AuthorEmail = strings.TrimSuffix(parts[1], ">")
		}
	case *pkg.GemMetadata:
		meta.Authors = strings.Split(author, ",")
	}
}
