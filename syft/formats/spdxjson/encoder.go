package spdxjson

import (
	"encoding/json"
	"io"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder2_3(output io.Writer, s sbom.SBOM) error {
	doc := spdxhelpers.ToFormatModel(s)
	return encodeJSON(output, doc)
}

func encoder2_2(output io.Writer, s sbom.SBOM) error {
	doc := spdxhelpers.ToFormatModel(s)

	var out v2_2.Document
	err := convert.Document(doc, &out)
	if err != nil {
		return err
	}

	return encodeJSON(output, out)
}

func encodeJSON(output io.Writer, doc interface{}) error {
	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(doc)
}
