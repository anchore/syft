package encoders

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/sbom"
)

type list struct {
	encoders []sbom.FormatEncoder
	err      error
}

func (l *list) addWithErr(name sbom.FormatID) func([]sbom.FormatEncoder, error) {
	return func(encs []sbom.FormatEncoder, err error) {
		if err != nil {
			l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: %w", name, err))
			return
		}
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}

func (l *list) add(name sbom.FormatID) func(...sbom.FormatEncoder) {
	return func(encs ...sbom.FormatEncoder) {
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}
