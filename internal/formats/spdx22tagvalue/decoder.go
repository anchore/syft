package spdx22tagvalue

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/tvloader"

	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	doc, err := tvloader.Load2_2(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode spdx-json: %w", err)
	}

	return spdxhelpers.ToSyftModel(doc)
}
