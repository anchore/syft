package cyclonedxutil

import (
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

func (d Decoder) Decode(r io.Reader) (*cyclonedx.BOM, error) {
	doc := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	}
	err := cyclonedx.NewBOMDecoder(r, d.format).Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
