package sbom

import (
	"errors"
	"io"
)

var (
	ErrEncodingNotSupported   = errors.New("encoding not supported")
	ErrDecodingNotSupported   = errors.New("decoding not supported")
	ErrValidationNotSupported = errors.New("validation not supported")
)

type FormatID string

type Format interface {
	ID() FormatID
	Encode(io.Writer, SBOM) error
	Decode(io.Reader) (*SBOM, error)
	Validate(io.Reader) error
}

type format struct {
	id        FormatID
	encoder   Encoder
	decoder   Decoder
	validator Validator
}

// Decoder is a function that can convert an SBOM document of a specific format from a reader into Syft native objects.
type Decoder func(reader io.Reader) (*SBOM, error)

// Encoder is a function that can transform Syft native objects into an SBOM document of a specific format written to the given writer.
type Encoder func(io.Writer, SBOM) error

// Validator reads the SBOM from the given reader and assesses whether the document conforms to the specific SBOM format.
// The validator should positively confirm if the SBOM is not only the format but also has the minimal set of values
// that the format requires. For example, all syftjson formatted documents have a schema section which should have
// "anchore/syft" within the version --if this isn't found then the validator should raise an error. These active
// assertions protect against "simple" format decoding validations that may lead to false positives (e.g. I decoded
// json successfully therefore this must be the target format, however, all values are their default zero-value and
// really represent a different format that also uses json)
type Validator func(reader io.Reader) error

func NewFormat(id FormatID, encoder Encoder, decoder Decoder, validator Validator) Format {
	return &format{
		id:        id,
		encoder:   encoder,
		decoder:   decoder,
		validator: validator,
	}
}

func (f format) ID() FormatID {
	return f.id
}

func (f format) Encode(output io.Writer, s SBOM) error {
	if f.encoder == nil {
		return ErrEncodingNotSupported
	}
	return f.encoder(output, s)
}

func (f format) Decode(reader io.Reader) (*SBOM, error) {
	if f.decoder == nil {
		return nil, ErrDecodingNotSupported
	}
	return f.decoder(reader)
}

func (f format) Validate(reader io.Reader) error {
	if f.validator == nil {
		return ErrValidationNotSupported
	}

	return f.validator(reader)
}
