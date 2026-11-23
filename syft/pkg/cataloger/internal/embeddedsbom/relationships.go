/*
Package embeddedsbom holds what catalogers that read an SBOM found within the scan share.
*/
package embeddedsbom

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// Relationships keeps the relationships decoded from an embedded SBOM that may enter the scan's own results. A
// file the SBOM nests within an archive, or makes the scan root, is nothing this scan found, and encoders would
// rebuild archives and roots from it.
func Relationships(relationships []artifact.Relationship) []artifact.Relationship {
	var out []artifact.Relationship
	for _, r := range relationships {
		if plainFile(r.From) && plainFile(r.To) {
			out = append(out, r)
		}
	}
	return out
}

// plainFile reports false for a file endpoint nested in an archive or at the scan root, and true otherwise.
func plainFile(v artifact.Identifiable) bool {
	var c file.Coordinates
	switch v := v.(type) {
	case file.Location:
		c = v.Coordinates
	case file.Coordinates:
		c = v
	default:
		return true
	}
	return c.FullPath == "" && c.RealPath != "" && c.RealPath != "/"
}
