package format

import (
	"fmt"
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/internal/stream"
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
func (c *DecoderCollection) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	if r == nil {
		return nil, "", "", fmt.Errorf("no SBOM bytes provided")
	}

	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", fmt.Errorf("unable to create a seekable reader: %w", err)
	}

	var bestID sbom.FormatID
	for _, d := range c.decoders {
		_, err = reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, "", "", fmt.Errorf("unable to seek to start of SBOM: %w", err)
		}
		id, version := d.Identify(reader)
		if id == "" || version == "" {
			if id != "" {
				bestID = id
			}
			continue
		}

		_, err = reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, "", "", fmt.Errorf("unable to seek to start of SBOM: %w", err)
		}
		return d.Decode(reader)
	}

	if bestID != "" {
		return nil, bestID, "", fmt.Errorf("sbom format found to be %q but the version is not supported", bestID)
	}

	return nil, "", "", fmt.Errorf("sbom format not recognized")
}

// Identify takes a set of bytes and attempts to identify the format of the SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	reader, err := stream.SeekableReader(r)
	if err != nil {
		log.Debugf("unable to create a seekable reader: %v", err)
		return "", ""
	}

	for _, d := range c.decoders {
		_, err = reader.Seek(0, io.SeekStart)
		if err != nil {
			log.Debugf("unable to seek to start of SBOM: %v", err)
		}
		id, version := d.Identify(reader)
		if id != "" && version != "" {
			return id, version
		}
	}
	return "", ""
}
