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
	Option Option
	Encoder
	Decoder
	Validator
}

func NewFormat(option Option, encoder Encoder, decoder Decoder, validator Validator) Format {
	return Format{
		Option:    option,
		Encoder:   encoder,
		Decoder:   decoder,
		Validator: validator,
	}
}

func (f Format) Encode(output io.Writer, s sbom.SBOM) error {
	if f.Encoder == nil {
		return ErrEncodingNotSupported
	}
	return f.Encoder.Encode(output, s)
}

func (f Format) Decode(reader io.Reader) (*sbom.SBOM, error) {
	if f.Decoder == nil {
		return nil, ErrDecodingNotSupported
	}
	return f.Decoder.Decode(reader)
}

func (f Format) Validate(reader io.Reader) error {
	if f.Validator == nil {
		return ErrValidationNotSupported
	}

	return f.Validator.Validate(reader)
}

func (f Format) Presenter(s sbom.SBOM) *Presenter {
	if f.Encoder == nil {
		return nil
	}
	return NewPresenter(f.Encoder, s)
}
