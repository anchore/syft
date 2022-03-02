package text

import (
	"github.com/anchore/syft/syft/sbom"
)

func Format(names ...string) sbom.Format {
	return sbom.NewFormat(
		encoder,
		nil,
		nil,
		append(names, "text")...,
	)
}
