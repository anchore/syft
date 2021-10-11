package spdx22json

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const anchoreNamespace = "https://anchore.com/syft"

func encoder(output io.Writer, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro) error {
	doc := toFormatModel(catalog, srcMetadata, d)

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")

	return enc.Encode(&doc)
}
