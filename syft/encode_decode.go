package syft

import (
	"io"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	return format.Encode(s, f)
}

// TODO: deprecated, moved to syft/formats/formats.go. will be removed in v1.0.0
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	return format.Decode(reader)
}
