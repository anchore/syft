package formats

import (
	"bytes"

	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/format"
)

// TODO: eventually this is the source of truth for all formatters
func All() []format.Format {
	return []format.Format{
		syftjson.Format(),
	}
}

func Identify(by []byte) (*format.Format, error) {
	for _, f := range All() {
		if f.Detect(bytes.NewReader(by)) {
			return &f, nil
		}
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
