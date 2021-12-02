package spdx22json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	doc, err := toFormatModel(s)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(doc)
}
