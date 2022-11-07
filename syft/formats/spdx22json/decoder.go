package spdx22json

import (
	"fmt"
	"io"

	spdx "github.com/spdx/tools-golang/json"

	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
)

func decoder(reader io.Reader) (s *sbom.SBOM, err error) {
	doc, err := spdx.Load2_3(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode spdx-json: %w", err)
	}

	return spdxhelpers.ToSyftModel(doc)
}
