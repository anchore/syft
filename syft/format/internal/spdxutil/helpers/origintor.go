package helpers

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

// Originator needs to conform to the SPDX spec here:
// https://spdx.github.io/spdx-spec/package-information/#76-package-originator-field
// Available options are: <omit>, NOASSERTION, Person: <person>, Organization: <org>
// return values are: <type>, <value>
func Originator(p pkg.Package) (string, string) {
	typ := ""
	author := ""
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			author = metadata.Maintainer
		case pkg.NpmPackage:
			author = metadata.Author
		case pkg.PythonPackage:
			author = metadata.Author
			if author == "" {
				author = metadata.AuthorEmail
			} else if metadata.AuthorEmail != "" {
				author = fmt.Sprintf("%s (%s)", author, metadata.AuthorEmail)
			}
		case pkg.RubyGemspec:
			if len(metadata.Authors) > 0 {
				author = metadata.Authors[0]
			}
		case pkg.RpmDBEntry:
			typ = "Organization"
			author = metadata.Vendor
		case pkg.DpkgDBEntry:
			author = metadata.Maintainer
		}
		if typ == "" && author != "" {
			typ = "Person"
		}
	}
	return typ, author
}
