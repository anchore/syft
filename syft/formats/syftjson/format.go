package syftjson

import (
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/sbom"
)

const ID sbom.FormatID = "syft-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		strings.SplitN(internal.JSONSchemaVersion, ".", 2)[0],
		encoder,
		decoder,
		validator,
		ID, "json", "syft",
	)
}
