package hadron

import (
	"github.com/anchore/packageurl-go"
)

// packageURL returns the canonical Hadron PURL: pkg:hadron/<name>@<version>.
// This must match Trivy's output so SBOMs reconcile across scanners.
func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		"hadron",
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
