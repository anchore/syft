package spdx22tagvalue

import (
	"io"

	"github.com/anchore/syft/syft/sbom"
	"github.com/spdx/tools-golang/tvsaver"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	model, err := toFormatModel(s)
	if err != nil {
		return err
	}
	return tvsaver.Save2_2(model, output)
}
