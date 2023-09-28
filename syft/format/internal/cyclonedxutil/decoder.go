package cyclonedxutil

import (
	"bytes"

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

func (d Decoder) Decode(by []byte) (*cyclonedx.BOM, error) {
	doc := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{},
	}
	err := cyclonedx.NewBOMDecoder(bytes.NewReader(by), d.format).Decode(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
