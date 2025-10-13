package spdxjson

import (
	"encoding/json"
	"io"

	spdx "github.com/spdx/tools-golang/spdx/v3/v3_0_1"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/sbom"
)

type spdx3Decoder struct{}

func (s spdx3Decoder) Decode(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	doc := spdx.NewDocument(spdx.ProfileIdentifierType_Software, "imported-sbom", &spdx.SoftwareAgent{
		Name: "syft", // FIXME from config
	}, &spdx.Tool{
		Name: "syft",
	})
	err := doc.FromJSON(reader)
	if err != nil {
		return nil, "", "", err
	}

	sb, err := spdxhelpers.ToSyftModelV3(doc)
	return sb, spdxutil.JSONFormatID, "", err
}

func (s spdx3Decoder) Identify(reader io.Reader) (sbom.FormatID, string) {
	type Document struct {
		Context string `json:"@context"`
	}

	dec := json.NewDecoder(reader)

	var doc Document
	if err := dec.Decode(&doc); err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	spdxVersion := ""

	switch doc.Context {
	case "https://spdx.org/rdf/3.0.1/spdx-context.jsonld":
		spdxVersion = spdxutil.V3_0_1
	}

	return spdxutil.JSONFormatID, spdxVersion
}
