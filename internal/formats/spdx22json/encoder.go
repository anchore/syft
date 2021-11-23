package spdx22json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

const anchoreNamespace = "https://anchore.com/syft"

func encoder(output io.Writer, s sbom.SBOM) error {
	doc := toFormatModel(s)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
