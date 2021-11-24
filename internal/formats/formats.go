package formats

import (
	"bytes"

	"github.com/anchore/syft/internal/formats/cyclonedx12xml"
	"github.com/anchore/syft/internal/formats/cyclonedx13json"
	"github.com/anchore/syft/internal/formats/cyclonedx13xml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"
	"github.com/anchore/syft/syft/format"
)

// TODO: eventually this is the source of truth for all formatters
func All() []format.Format {
	return []format.Format{
		syftjson.Format(),
		table.Format(),
		cyclonedx12xml.Format(),
		cyclonedx13xml.Format(),
		cyclonedx13json.Format(),
		spdx22json.Format(),
		spdx22tagvalue.Format(),
		text.Format(),
	}
}

func Identify(by []byte) (*format.Format, error) {
	for _, f := range All() {
		if err := f.Validate(bytes.NewReader(by)); err != nil {
			continue
		}
		return &f, nil
	}
	return nil, nil
}

func ByOption(option format.Option) *format.Format {
	for _, f := range All() {
		if f.Option == option {
			return &f
		}
	}
	return nil
}
