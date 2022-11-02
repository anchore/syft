package spdx22tagvalue

import (
	"io"

	"github.com/spdx/tools-golang/tvsaver"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	model := spdxhelpers.ToFormatModel(s)
	return tvsaver.Save2_3(model, output)
}
