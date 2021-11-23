package format

import (
	"errors"
	"io"

	"github.com/anchore/syft/syft/sbom"
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

func (f Format) Encode(output io.Writer, s sbom.SBOM) error {
	if f.encoder == nil {
		return ErrEncodingNotSupported
	}
	return f.encoder(output, s)
}

func (f Format) Decode(reader io.Reader) (*sbom.SBOM, error) {
	if f.decoder == nil {
		return nil, ErrDecodingNotSupported
	}
	return f.decoder(reader)
}

func (f Format) Validate(reader io.Reader) error {
	if f.validator == nil {
		return ErrValidationNotSupported
	}

	return f.validator(reader)
}

func (f Format) Presenter(s sbom.SBOM) *Presenter {
	if f.encoder == nil {
		return nil
	}
	return NewPresenter(f.encoder, s)
}
