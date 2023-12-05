package options

import (
	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/sbom"
)

type FormatCyclonedxXML struct {
	Pretty *bool `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
}

func DefaultFormatCyclonedxXML() FormatCyclonedxXML {
	return FormatCyclonedxXML{}
}

func (o FormatCyclonedxXML) formatEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxxml.SupportedVersions() {
		enc, err := cyclonedxxml.NewFormatEncoderWithConfig(o.buildConfig(v))
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o FormatCyclonedxXML) buildConfig(version string) cyclonedxxml.EncoderConfig {
	var pretty bool
	if o.Pretty != nil {
		pretty = *o.Pretty
	}
	return cyclonedxxml.EncoderConfig{
		Version: version,
		Pretty:  pretty,
	}
}
