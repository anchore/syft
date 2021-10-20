package format

import (
	"errors"
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var (
	ErrEncodingNotSupported   = errors.New("encoding not supported")
	ErrDecodingNotSupported   = errors.New("decoding not supported")
	ErrValidationNotSupported = errors.New("validation not supported")
)

type Format struct {
	Option    Option
	encoder   Encoder
	decoder   Decoder
	validator Validator
}

func NewFormat(option Option, encoder Encoder, decoder Decoder, validator Validator) Format {
	return Format{
		Option:    option,
		encoder:   encoder,
		decoder:   decoder,
		validator: validator,
	}
}

func (f Format) Encode(output io.Writer, catalog *pkg.Catalog, d *distro.Distro, metadata *source.Metadata, scope source.Scope) error {
	if f.encoder == nil {
		return ErrEncodingNotSupported
	}
	return f.encoder(output, catalog, metadata, d, scope)
}

func (f Format) Decode(reader io.Reader) (*pkg.Catalog, *source.Metadata, *distro.Distro, source.Scope, error) {
	if f.decoder == nil {
		return nil, nil, nil, source.UnknownScope, ErrDecodingNotSupported
	}
	return f.decoder(reader)
}

func (f Format) Validate(reader io.Reader) error {
	if f.validator == nil {
		return ErrValidationNotSupported
	}

	return f.validator(reader)
}

func (f Format) Presenter(catalog *pkg.Catalog, metadata *source.Metadata, d *distro.Distro, scope source.Scope) *Presenter {
	if f.encoder == nil {
		return nil
	}
	return NewPresenter(f.encoder, catalog, metadata, d, scope)
}
