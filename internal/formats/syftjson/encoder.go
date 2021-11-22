package syftjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

type encoder struct {
	appConfig interface{}
}

func (e encoder) Encode(output io.Writer, s sbom.SBOM) error {
	doc := ToFormatModel(s, e.appConfig)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
