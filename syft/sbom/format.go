package sbom

import (
	"io"
)

type FormatID string

// String returns a string representation of the FormatID.
func (f FormatID) String() string {
	return string(f)
}

const AnyVersion = ""

type FormatEncoder interface {
	ID() FormatID
	Aliases() []string
	Version() string
	Encode(io.Writer, SBOM) error
}

type FormatDecoder interface {
	Decode(by []byte) (*SBOM, FormatID, string, error)
	Identify(by []byte) (FormatID, string)
}
