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
	// TODO comment: should this be Decode(by []byte) (*SBOM, error)
	// TODO comment: missing explanation of expectations for usage and return values
	Decode(by []byte) (*SBOM, FormatID, string, error)
	// TODO comment: can we get rid of this?
	Identify(by []byte) (FormatID, string)
}
