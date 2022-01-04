package spdx22json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/sbom"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode spdx-json: %w", err)
	}

	return toSyftModel(doc)
}
