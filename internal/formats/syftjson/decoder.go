package syftjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func decoder(reader io.Reader) (*pkg.Catalog, *source.Metadata, *distro.Distro, error) {
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to decode syft-json: %w", err)
	}

	return toSyftModel(doc)
}
