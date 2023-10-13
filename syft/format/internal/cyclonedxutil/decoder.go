package cyclonedxutil

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
)

type Decoder struct {
	format cyclonedx.BOMFileFormat
}

func NewDecoder(format cyclonedx.BOMFileFormat) Decoder {
	return Decoder{
		format: format,
	}
}

func (d Decoder) Decode(reader io.ReadSeeker) (*cyclonedx.BOM, error) {
	doc := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to start of CycloneDX SBOM: %w", err)
	}
	err := cyclonedx.NewBOMDecoder(reader, d.format).Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
