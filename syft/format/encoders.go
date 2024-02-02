package format

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/sbom"
)

const AllVersions = "all-versions"

type EncodersConfig struct {
	Template      template.EncoderConfig
	SyftJSON      syftjson.EncoderConfig
	SPDXJSON      spdxjson.EncoderConfig
	SPDXTagValue  spdxtagvalue.EncoderConfig
	CyclonedxJSON cyclonedxjson.EncoderConfig
	CyclonedxXML  cyclonedxxml.EncoderConfig
}

func Encoders() []sbom.FormatEncoder {
	encs, _ := DefaultEncodersConfig().Encoders()
	return encs
}

func DefaultEncodersConfig() EncodersConfig {
	cfg := EncodersConfig{
		Template:      template.DefaultEncoderConfig(),
		SyftJSON:      syftjson.DefaultEncoderConfig(),
		SPDXJSON:      spdxjson.DefaultEncoderConfig(),
		SPDXTagValue:  spdxtagvalue.DefaultEncoderConfig(),
		CyclonedxJSON: cyclonedxjson.DefaultEncoderConfig(),
		CyclonedxXML:  cyclonedxxml.DefaultEncoderConfig(),
	}

	// empty value means to support all versions
	cfg.SPDXJSON.Version = AllVersions
	cfg.SPDXTagValue.Version = AllVersions
	cfg.CyclonedxJSON.Version = AllVersions
	cfg.CyclonedxXML.Version = AllVersions

	return cfg
}

func (o EncodersConfig) Encoders() ([]sbom.FormatEncoder, error) {
	var l encodersList

	if o.Template.TemplatePath != "" {
		l.addWithErr(template.ID)(o.templateEncoders())
	}

	l.addWithErr(syftjson.ID)(o.syftJSONEncoders())
	l.add(table.ID)(table.NewFormatEncoder())
	l.add(text.ID)(text.NewFormatEncoder())
	l.add(github.ID)(github.NewFormatEncoder())
	l.addWithErr(cyclonedxxml.ID)(o.cyclonedxXMLEncoders())
	l.addWithErr(cyclonedxjson.ID)(o.cyclonedxJSONEncoders())
	l.addWithErr(spdxjson.ID)(o.spdxJSONEncoders())
	l.addWithErr(spdxtagvalue.ID)(o.spdxTagValueEncoders())

	return l.encoders, l.err
}

func (o EncodersConfig) templateEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := template.NewFormatEncoder(o.Template)
	return []sbom.FormatEncoder{enc}, err
}

func (o EncodersConfig) syftJSONEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := syftjson.NewFormatEncoderWithConfig(o.SyftJSON)
	return []sbom.FormatEncoder{enc}, err
}

func (o EncodersConfig) cyclonedxXMLEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.CyclonedxXML

	var versions []string
	if cfg.Version == AllVersions {
		versions = cyclonedxxml.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := cyclonedxxml.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) cyclonedxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.CyclonedxJSON

	var versions []string
	if cfg.Version == AllVersions {
		versions = cyclonedxjson.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) spdxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.SPDXJSON

	var versions []string
	if cfg.Version == AllVersions {
		versions = spdxjson.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := spdxjson.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) spdxTagValueEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.SPDXTagValue

	var versions []string
	if cfg.Version == AllVersions {
		versions = spdxtagvalue.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

type encodersList struct {
	encoders []sbom.FormatEncoder
	err      error
}

func (l *encodersList) addWithErr(name sbom.FormatID) func([]sbom.FormatEncoder, error) {
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

func (l *encodersList) add(name sbom.FormatID) func(...sbom.FormatEncoder) {
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
