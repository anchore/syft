package spdxtagvalue

import (
	"io"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/tagvalue"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder2_3(output io.Writer, s sbom.SBOM) error {
	model := spdxhelpers.ToFormatModel(s)
	return tagvalue.Write(model, output)
}

func encoder2_2(output io.Writer, s sbom.SBOM) error {
	model := spdxhelpers.ToFormatModel(s)
	var out v2_2.Document
	err := convert.Document(model, &out)
	if err != nil {
		return err
	}
	return tagvalue.Write(out, output)
}

func encoder2_1(output io.Writer, s sbom.SBOM) error {
	model := spdxhelpers.ToFormatModel(s)
	var out v2_1.Document
	err := convert.Document(model, &out)
	if err != nil {
		return err
	}
	return tagvalue.Write(out, output)
}
