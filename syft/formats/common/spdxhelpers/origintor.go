package spdxhelpers

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

// Originator needs to conform to the SPDX spec here:
// https://spdx.github.io/spdx-spec/package-information/#76-package-originator-field
// Available options are: <omit>, NOASSERTION, Person: <person>, Organization: <org>
func Originator(p pkg.Package) string {
	if hasMetadata(p) {
		author := ""
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
		case pkg.RpmdbMetadata:
			return "Organization: " + metadata.Vendor
		case pkg.DpkgMetadata:
			author = metadata.Maintainer
		}
		if author != "" {
			return "Person: " + author
		}
	}
	return ""
}
