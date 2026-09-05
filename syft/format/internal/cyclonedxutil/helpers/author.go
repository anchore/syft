package helpers

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/pkg"
)

func encodeAuthor(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.NpmPackage:
			return metadata.Author
		case pkg.PythonPackage:
			author := metadata.Author
			if metadata.AuthorEmail != "" {
				if author == "" {
					return metadata.AuthorEmail
				}
				author += fmt.Sprintf(" <%s>", metadata.AuthorEmail)
			}
			return author
		case pkg.RubyGemspec:
			if len(metadata.Authors) > 0 {
				return strings.Join(metadata.Authors, ",")
			}
			return ""
		}
	}
	return ""
}

func decodeAuthor(author string, metadata any) {
	switch meta := metadata.(type) {
	case *pkg.NpmPackage:
		meta.Author = author
	case *pkg.PythonPackage:
		parts := strings.SplitN(author, " <", 2)
		meta.Author = parts[0]
		if len(parts) > 1 {
			meta.AuthorEmail = strings.TrimSuffix(parts[1], ">")
		}
	case *pkg.RubyGemspec:
		meta.Authors = strings.Split(author, ",")
	}
}

// ConvertComponentAuthors rewrites the deprecated component author field into the authors list that replaced it
// in CycloneDX 1.6.
//
// The format model is built with the deprecated field, since that is the only one earlier spec versions have,
// so the translation happens on the way out and only for targets that can express the replacement. Both fields
// remain valid in 1.6 and later, but a document should not be written with a field the spec has deprecated when
// the current one says the same thing.
//
// source: https://cyclonedx.org/docs/1.6/json/#components_items_author
func ConvertComponentAuthors(bom *cyclonedx.BOM, version cyclonedx.SpecVersion) {
	if bom == nil || version < cyclonedx.SpecVersion1_6 {
		return
	}

	if bom.Metadata != nil {
		convertComponentAuthor(bom.Metadata.Component)

		if bom.Metadata.Tools != nil {
			convertComponentAuthors(bom.Metadata.Tools.Components)
		}
	}

	convertComponentAuthors(bom.Components)
}

func convertComponentAuthors(components *[]cyclonedx.Component) {
	if components == nil {
		return
	}

	for i := range *components {
		convertComponentAuthor(&(*components)[i])
	}
}

func convertComponentAuthor(c *cyclonedx.Component) {
	if c == nil {
		return
	}

	// a component may carry components of its own, each with an author of its own
	convertComponentAuthors(c.Components)

	if c.Author == "" || c.Authors != nil {
		return
	}

	c.Authors = &[]cyclonedx.OrganizationalContact{authorContact(c.Author)}
	c.Author = ""
}

// authorContact splits an author into a contact, recognizing only the "name <email>" form that encodeAuthor
// produces. Where syft has more than one author to describe it joins them with a separator of the ecosystem's
// own choosing, so splitting that string apart here would mean guessing at a convention that differs per
// ecosystem -- and guessing wrong would change what the document claims. Carrying the value across whole says
// exactly what the deprecated field said, and no more.
func authorContact(author string) cyclonedx.OrganizationalContact {
	name, email, found := strings.Cut(author, " <")
	if !found {
		return cyclonedx.OrganizationalContact{Name: author}
	}

	return cyclonedx.OrganizationalContact{
		Name:  name,
		Email: strings.TrimSuffix(email, ">"),
	}
}

// componentAuthor reads the author of a component regardless of which of the two fields the document used to
// state it, so that a 1.6 document -- syft's own output included -- decodes to the same package metadata as the
// equivalent 1.5 one.
func componentAuthor(c *cyclonedx.Component) string {
	if c.Authors == nil || len(*c.Authors) == 0 {
		return c.Author
	}

	authors := make([]string, 0, len(*c.Authors))
	for _, a := range *c.Authors {
		switch {
		case a.Name != "" && a.Email != "":
			authors = append(authors, fmt.Sprintf("%s <%s>", a.Name, a.Email))
		case a.Name != "":
			authors = append(authors, a.Name)
		case a.Email != "":
			authors = append(authors, a.Email)
		}
	}

	if len(authors) == 0 {
		return c.Author
	}

	return strings.Join(authors, ",")
}
