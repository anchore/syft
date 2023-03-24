package spdxhelpers

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
		case pkg.ApkMetadata:
			author = metadata.Maintainer
		case pkg.NpmPackageJSONMetadata:
			author = metadata.Author
		case pkg.PythonPackageMetadata:
			author = metadata.Author
			if author == "" {
				author = metadata.AuthorEmail
			} else if metadata.AuthorEmail != "" {
				author = fmt.Sprintf("%s (%s)", author, metadata.AuthorEmail)
			}
		case pkg.GemMetadata:
			if len(metadata.Authors) > 0 {
				author = metadata.Authors[0]
			}
		case pkg.RpmMetadata:
			typ = "Organization"
			author = metadata.Vendor
		case pkg.DpkgMetadata:
			author = metadata.Maintainer
		}
		if typ == "" && author != "" {
			typ = "Person"
		}
	}
	return typ, author
}
