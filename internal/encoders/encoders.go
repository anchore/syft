package encoders

import (
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

type Formats struct {
	Template      template.EncoderConfig
	SyftJSON      syftjson.EncoderConfig
	SPDXJSON      spdxjson.EncoderConfig
	SPDXTagValue  spdxtagvalue.EncoderConfig
	CyclonedxJSON cyclonedxjson.EncoderConfig
	CyclonedxXML  cyclonedxxml.EncoderConfig
}

func DefaultFormats() Formats {
	return Formats{
		Template:      template.DefaultEncoderConfig(),
		SyftJSON:      syftjson.DefaultEncoderConfig(),
		SPDXJSON:      spdxjson.DefaultEncoderConfig(),
		SPDXTagValue:  spdxtagvalue.DefaultEncoderConfig(),
		CyclonedxJSON: cyclonedxjson.DefaultEncoderConfig(),
		CyclonedxXML:  cyclonedxxml.DefaultEncoderConfig(),
	}
}

func (o Formats) EncoderForAllVersions() ([]sbom.FormatEncoder, error) {
	var l list

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

func (o Formats) templateEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := template.NewFormatEncoder(template.EncoderConfig{
		TemplatePath: o.Template.TemplatePath,
	})
	return []sbom.FormatEncoder{enc}, err
}

func (o Formats) syftJSONEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := syftjson.NewFormatEncoderWithConfig(o.SyftJSON)
	return []sbom.FormatEncoder{enc}, err
}

func (o Formats) cyclonedxXMLEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxxml.SupportedVersions() {
		o.CyclonedxXML.Version = v
		enc, err := cyclonedxxml.NewFormatEncoderWithConfig(o.CyclonedxXML)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o Formats) cyclonedxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range cyclonedxjson.SupportedVersions() {
		o.CyclonedxJSON.Version = v
		enc, err := cyclonedxjson.NewFormatEncoderWithConfig(o.CyclonedxJSON)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o Formats) spdxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range spdxjson.SupportedVersions() {
		o.SPDXJSON.Version = v
		enc, err := spdxjson.NewFormatEncoderWithConfig(o.SPDXJSON)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o Formats) spdxTagValueEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)
	for _, v := range spdxtagvalue.SupportedVersions() {
		o.SPDXTagValue.Version = v
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(o.SPDXTagValue)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}
