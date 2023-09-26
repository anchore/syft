package spdxjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/sbom"
	spdxJson "github.com/spdx/tools-golang/json"
	"strings"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	// since spdx lib will always return the latest version of the document, we need to identify the version
	// first and then decode into the appropriate document object. Otherwise if we get the version info from the
	// decoded object we will always get the latest version (instead of the version we decoded from).
	id, version := d.Identify(by)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a spdx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported spdx json document version")
	}

	doc, err := spdxJson.Read(bytes.NewReader(by))
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode spdx json: %w", err)
	}

	s, err := spdxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}
	return s, id, version, nil
}

func (d decoder) Identify(by []byte) (sbom.FormatID, string) {
	// Example JSON document
	// {
	// "spdxVersion": "SPDX-2.3",
	// ...
	type Document struct {
		SPDXVersion string `json:"spdxVersion"`
	}

	var doc Document
	err := json.Unmarshal(by, &doc)
	if err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	id, version := getFormatInfo(doc.SPDXVersion)
	if version == "" || id != ID {
		// not a spdx json document that we support
		return "", ""
	}

	return id, version
}

func getFormatInfo(spdxVersion string) (sbom.FormatID, string) {
	// example input: SPDX-2.3
	if !strings.HasPrefix(strings.ToLower(spdxVersion), "spdx-") {
		return "", ""
	}
	fields := strings.Split(spdxVersion, "-")
	if len(fields) != 2 {
		return ID, ""
	}

	return ID, fields[1]
}
