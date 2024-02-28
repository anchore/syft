package cyclonedxutil

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/format/internal/stream"
)

type Decoder struct {
	format cyclonedx.BOMFileFormat
}

func NewDecoder(format cyclonedx.BOMFileFormat) Decoder {
	return Decoder{
		format: format,
	}
}

func (d Decoder) Decode(r io.Reader) (*cyclonedx.BOM, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, err
	}

	doc := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to start of CycloneDX SBOM: %w", err)
	}

	err = cyclonedx.NewBOMDecoder(reader, d.format).Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
