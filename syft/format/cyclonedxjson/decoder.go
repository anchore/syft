package cyclonedxjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/sbom"
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

func (d decoder) Decode(reader io.ReadSeeker) (*sbom.SBOM, sbom.FormatID, string, error) {
	if reader == nil {
		return nil, "", "", fmt.Errorf("no SBOM bytes provided")
	}
	id, version := d.Identify(reader)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a cyclonedx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported cyclonedx json document version")
	}

	doc, err := d.decoder.Decode(reader)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode cyclonedx json document: %w", err)
	}

	s, err := cyclonedxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}

	return s, id, version, nil
}

func (d decoder) Identify(reader io.ReadSeeker) (sbom.FormatID, string) {
	if reader == nil {
		return "", ""
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		log.Debugf("unable to seek to start of CycloneDX JSON SBOM: %+v", err)
		return "", ""
	}

	type Document struct {
		JSONSchema  string `json:"$schema"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}

	dec := json.NewDecoder(reader)

	var doc Document
	err := dec.Decode(&doc)
	if err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	id, version := getFormatInfo(doc.BOMFormat, doc.SpecVersion)
	if version == "" || id != ID {
		// not a cyclonedx json document that we support
		return "", ""
	}

	return id, version
}

func getFormatInfo(bomFormat string, specVersion any) (sbom.FormatID, string) {
	if bomFormat != "CycloneDX" {
		// not a cyclonedx json document
		return "", ""
	}

	// by this point, it looks to be cyclonedx json, but we need to know the version

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
