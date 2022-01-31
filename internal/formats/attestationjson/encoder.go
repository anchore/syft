package attestationjson

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	// TODO: which format do we convert to here
	return nil
}
