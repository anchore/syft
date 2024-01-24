package format

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*DecoderCollection)(nil)

type DecoderCollection struct {
	decoders []sbom.FormatDecoder
}

func NewDecoderCollection(decoders ...sbom.FormatDecoder) sbom.FormatDecoder {
	return &DecoderCollection{
		decoders: decoders,
	}
}

// Decode takes a set of bytes and attempts to decode it into an SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Decode(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	if reader == nil {
		return nil, "", "", fmt.Errorf("no SBOM bytes provided")
	}
	var bestID sbom.FormatID
	for _, d := range c.decoders {
		id, version := d.Identify(reader)
		if id == "" || version == "" {
			if id != "" {
				bestID = id
			}
			continue
		}

		return d.Decode(reader)
	}

	if bestID != "" {
		return nil, bestID, "", fmt.Errorf("sbom format found to be %q but the version is not supported", bestID)
	}

	return nil, "", "", fmt.Errorf("sbom format not recognized")
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Identify(reader io.Reader) (sbom.FormatID, string) {
	if reader == nil {
		return "", ""
	}
	for _, d := range c.decoders {
		id, version := d.Identify(reader)
		if id != "" && version != "" {
			return id, version
		}
	}
	return "", ""
}
