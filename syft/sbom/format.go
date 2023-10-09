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
	// Decode will return an SBOM from the given set of bytes. If the bytes are not a valid SBOM for the given format
	// then an error will be returned.
	Decode(by []byte) (*SBOM, FormatID, string, error)

	// Identify will return the format ID and version for the given set of bytes. Note: this does not validate the
	// full SBOM, only pulls the minimal information necessary to identify the format.
	Identify(by []byte) (FormatID, string)
}
