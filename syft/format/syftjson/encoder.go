package syftjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatEncoder = (*encoder)(nil)

const ID sbom.FormatID = "syft-json"

type encoder struct {
}

func DefaultFormatEncoder() sbom.FormatEncoder {
	return encoder{}
}

func (e encoder) ID() sbom.FormatID {
	return ID
}

func (e encoder) Aliases() []string {
	return []string{
		"json",
		"syft",
	}
}

func (e encoder) Version() string {
	return internal.JSONSchemaVersion
}

func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	doc := ToFormatModel(s)

	enc := json.NewEncoder(writer)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
