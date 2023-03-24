package portage

import (
	"github.com/anchore/packageurl-go"
)

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		"ebuild", // currently this is the proposed type for portage packages at https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
