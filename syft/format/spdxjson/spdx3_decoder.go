package spdxjson

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/spdx/tools-golang/spdx/v3/v3_0"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/sbom"
)

var spdx3_0contextRegex = spdxContextRegex(spdxutil.V3_0)

func decodeSpdx3(version string, reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	switch version {
	case spdxutil.V3_0:
		doc := v3_0.NewDocument(v3_0.ProfileIdentifierType_Software, "", nil, nil)
		err := doc.FromJSON(reader)
		if err != nil {
			return nil, "", "", err
		}
		sb, err := spdxhelpers.ToSyftModelV3(doc)
		return sb, spdxutil.JSONFormatID, spdxutil.V3_0, err
	default:
		return nil, "", "", fmt.Errorf("unsupported version: %v", version)
	}
}

func identifySpdx3(reader io.Reader) (sbom.FormatID, string) {
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

	switch {
	case doc.Context == "":
	case spdx3_0contextRegex.MatchString(doc.Context):
		spdxVersion = spdxutil.V3_0
	default:
	}

	return spdxutil.JSONFormatID, spdxVersion
}

func spdxContextRegex(minorVersion string) *regexp.Regexp {
	// today this is "3.0.1", but is likely to be changed to only include the minor version "3.0"
	return regexp.MustCompile(regexp.QuoteMeta("https://spdx.org/rdf/") + minorVersion + `(\.\d+)?` + regexp.QuoteMeta("/spdx-context.jsonld"))
}
