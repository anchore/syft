package syftjson

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encoder(output io.Writer, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro) error {
	// TODO: application config not available yet
	doc := ToFormatModel(catalog, srcMetadata, d, nil)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
