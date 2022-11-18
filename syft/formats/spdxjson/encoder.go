package spdxjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	doc := spdxhelpers.ToFormatModel(s)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(doc)
}
