package syftjson

import (
	"github.com/anchore/syft/syft/sbom"
)

func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		decoder,
		validator,
		append(names, "syft-json", "json")...,
	)
}
