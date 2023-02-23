package syftjson

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		internal.JSONSchemaVersion,
		encoder,
		decoder,
		validator,
		ID, "json", "syft",
	)
}
