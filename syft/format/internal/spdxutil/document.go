package spdxutil

import (
	"fmt"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const DefaultVersion = "2.3"

func DocumentPrototypeFromVersion(v string) (any, error) {
	switch v {
	case "2.1":
		return v2_1.Document{}, nil
	case "2.2":
		return v2_2.Document{}, nil
	case "2.3", "", "2", "2.x":
		return v2_3.Document{}, nil
	}
	return nil, fmt.Errorf("unsupported SPDX version %q", v)
}

func ToDocument(s sbom.SBOM, to any) error {
	if to == nil {
		return fmt.Errorf("no SPDX prototype document provided to unmarshal into")
	}
	latestDoc := spdxhelpers.ToFormatModel(s)
	err := convert.Document(latestDoc, to)
	if err != nil {
		return err
	}
	return nil
}
