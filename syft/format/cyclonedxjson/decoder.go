package cyclonedxjson

import (
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
	"strings"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
	decoder cyclonedxutil.Decoder
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{
		decoder: cyclonedxutil.NewDecoder(cyclonedx.BOMFileFormatJSON),
	}
}

func (d decoder) Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	id, version := d.Identify(by)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a cyclonedx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported cyclonedx json document version")
	}

	doc, err := d.decoder.Decode(by)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode cyclonedx json document: %w", err)
	}

	s, err := cyclonedxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}

	return s, id, version, nil
}

func (d decoder) Identify(by []byte) (sbom.FormatID, string) {
	type Document struct {
		JSONSchema  string `json:"$schema"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}

	var doc Document
	err := json.Unmarshal(by, &doc)
	if err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	id, version := getFormatInfo(doc.JSONSchema, doc.BOMFormat, doc.SpecVersion)
	if version == "" || id != ID {
		// not a cyclonedx json document that we support
		return "", ""
	}

	return id, version
}

func getFormatInfo(schemaURI, bomFormat string, specVersion any) (sbom.FormatID, string) {
	// xmlns should be something like http://cyclonedx.org/schema/bom-1.4.schema.json
	if !strings.Contains(schemaURI, "cyclonedx.org/schema/bom") {
		// not a cyclonedx json document
		return "", ""
	}

	if bomFormat != "CycloneDX" {
		// not a cyclonedx json document
		return "", ""
	}

	// by this point this looks to be valid cyclonedx json, but we need to know the version

	var (
		version string
		spec    cyclonedx.SpecVersion
		err     error
	)
	switch s := specVersion.(type) {
	case string:
		version = s
		spec, err = cyclonedxutil.SpecVersionFromString(version)
		if err != nil {
			// not a supported version, but is cyclonedx json
			return ID, ""
		}
	case cyclonedx.SpecVersion:
		spec = s
		version = cyclonedxutil.VersionFromSpecVersion(spec)
		if version == "" {
			// not a supported version, but is cyclonedx json
			return ID, ""
		}
	default:
		// bad input provided for version info
		return ID, ""
	}

	if spec < 0 {
		// not a supported version, but is cyclonedx json
		return ID, ""
	}

	return ID, version
}
