package helpers

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
)

// Originator needs to conform to the SPDX spec here:
// https://spdx.github.io/spdx-spec/v2.2.2/package-information/#76-package-originator-field
//
// Definition:
//
//	If the package identified in the SPDX document originated from a different person or
//	organization than identified as Package Supplier (see 7.5 above), this field identifies from
//	where or whom the package originally came. In some cases, a package may be created and
//	originally distributed by a different third party than the Package Supplier of the package.
//	For example, the SPDX document identifies the package as glibc and the Package Supplier as
//	Red Hat, but the Free Software Foundation is the Package Originator.
//
// Use NOASSERTION if:
//
//   - the SPDX document creator has attempted to but cannot reach a reasonable objective determination;
//   - the SPDX document creator has made no attempt to determine this field; or
//   - the SPDX document creator has intentionally provided no information (no meaning should be implied by doing so).
//
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
