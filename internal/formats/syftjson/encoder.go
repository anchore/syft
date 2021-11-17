package syftjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

func encoder(output io.Writer, s sbom.SBOM, appConfig interface{}) error {
	// TODO: application config not available yet
	doc := ToFormatModel(s, appConfig)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
