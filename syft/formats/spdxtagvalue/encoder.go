package spdxtagvalue

import (
	"io"

	"github.com/spdx/tools-golang/tagvalue"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	model := spdxhelpers.ToFormatModel(s)
	return tagvalue.Write(model, output)
}
