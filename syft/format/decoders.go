package format

import (
	"fmt"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

var (
	staticDecoders sbom.FormatDecoder
	_              sbom.FormatDecoder = (*DecoderCollection)(nil)
)

func init() {
	staticDecoders = NewDecoderCollection(DefaultDecoders()...)
}

func DefaultDecoders() []sbom.FormatDecoder {
	return []sbom.FormatDecoder{
		syftjson.NewFormatDecoder(),
		cyclonedxxml.NewFormatDecoder(),
		cyclonedxjson.NewFormatDecoder(),
		spdxtagvalue.NewFormatDecoder(),
		spdxjson.NewFormatDecoder(),
	}
}

type DecoderCollection struct {
	decoders []sbom.FormatDecoder
}

func NewDecoderCollection(decoders ...sbom.FormatDecoder) sbom.FormatDecoder {
	return &DecoderCollection{
		decoders: decoders,
	}
}

// Decode takes a set of bytes and attempts to decode it into an SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	var bestID sbom.FormatID
	for _, d := range c.decoders {
		id, version := d.Identify(by)
		if id == "" || version == "" {
			if id != "" {
				bestID = id
			}
			continue
		}

		return d.Decode(by)
	}

	if bestID != "" {
		return nil, bestID, "", fmt.Errorf("sbom format found to be %q but the version is not supported", bestID)
	}

	return nil, "", "", fmt.Errorf("sbom format not recognized")
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Identify(by []byte) (sbom.FormatID, string) {
	for _, d := range c.decoders {
		id, version := d.Identify(by)
		if id != "" && version != "" {
			return id, version
		}
	}
	return "", ""
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM.
func Identify(by []byte) (sbom.FormatID, string) {
	return staticDecoders.Identify(by)
}

// Decode takes a set of bytes and attempts to decode it into an SBOM.
func Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	return staticDecoders.Decode(by)
}
