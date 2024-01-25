package format

import (
	"io"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

var staticDecoders sbom.FormatDecoder

func init() {
	staticDecoders = NewDecoderCollection(Decoders()...)
}

func Decoders() []sbom.FormatDecoder {
	return []sbom.FormatDecoder{
		syftjson.NewFormatDecoder(),
		cyclonedxxml.NewFormatDecoder(),
		cyclonedxjson.NewFormatDecoder(),
		spdxtagvalue.NewFormatDecoder(),
		spdxjson.NewFormatDecoder(),
	}
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM.
func Identify(reader io.ReadSeeker) (sbom.FormatID, string) {
	return staticDecoders.Identify(reader)
}

// Decode takes a set of bytes and attempts to decode it into an SBOM.
func Decode(reader io.ReadSeeker) (*sbom.SBOM, sbom.FormatID, string, error) {
	return staticDecoders.Decode(reader)
}
