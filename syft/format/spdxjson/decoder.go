package spdxjson

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	spdxJson "github.com/spdx/tools-golang/json"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", err
	}

	// since spdx lib will always return the latest version of the document, we need to identify the version
	// first and then decode into the appropriate document object. Otherwise if we get the version info from the
	// decoded object we will always get the latest version (instead of the version we decoded from).
	id, version := d.Identify(reader)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a spdx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported spdx json document version")
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", fmt.Errorf("unable to seek to start of SPDX JSON SBOM: %+v", err)
	}

	doc, err := spdxJson.Read(reader)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode spdx json: %w", err)
	}

	s, err := spdxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}
	return s, id, version, nil
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return "", ""
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		log.Debugf("unable to seek to start of SPDX JSON SBOM: %+v", err)
		return "", ""
	}

	// Example JSON document
	// {
	// "spdxVersion": "SPDX-2.3",
	// ...
	type Document struct {
		SPDXVersion string `json:"spdxVersion"`
	}

	dec := json.NewDecoder(reader)

	var doc Document
	if err = dec.Decode(&doc); err != nil {
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
