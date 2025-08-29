package helpers

import (
	"encoding/json"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func EncodeAuthors(p pkg.Package) *[]cyclonedx.OrganizationalContact {
	if metadata, ok := p.Metadata.(pkg.NpmPackage); ok && hasMetadata(p) {
		if metadata.Authors == "" {
			return nil
		}
		// The Authors field is a JSON string, so we need to unmarshal it first.
		var people []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}

		if err := json.Unmarshal([]byte(metadata.Authors), &people); err != nil {
			return nil
		}

		if len(people) == 0 {
			return nil
		}

		out := make([]cyclonedx.OrganizationalContact, 0, len(people))
		for _, p := range people {
			out = append(out, cyclonedx.OrganizationalContact{
				Name:  p.Name,
				Email: p.Email,
			})
		}
		return &out
	}
	return nil
}

func decodeAuthors(authors *[]cyclonedx.OrganizationalContact, metadata interface{}) {
	if meta, ok := metadata.(*pkg.NpmPackage); ok {
		if authors == nil {
			meta.Authors = ""
			return
		}
		b, err := json.Marshal(*authors)
		if err != nil {
			meta.Authors = ""
			return
		}
		meta.Authors = string(b)
	}
}
