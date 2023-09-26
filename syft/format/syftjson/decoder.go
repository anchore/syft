package syftjson

import (
	"encoding/json"
	"fmt"
	"github.com/Masterminds/semver"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct{}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(by []byte) (*sbom.SBOM, sbom.FormatID, string, error) {
	id, version := d.Identify(by)
	if version == "" || id != ID {
		return nil, "", "", fmt.Errorf("not a syft-json document")
	}
	var doc model.Document

	err := json.Unmarshal(by, &doc)
	if err != nil {
		return nil, "", "", fmt.Errorf("unable to decode syft-json document: %w", err)
	}

	if err := checkSupportedSchema(doc.Schema.Version, internal.JSONSchemaVersion); err != nil {
		log.Warn(err)
	}

	s, err := toSyftModel(doc)
	if err != nil {
		return nil, ID, doc.Schema.Version, fmt.Errorf("unable to transform to syft document model: %w", err)
	}

	return s, ID, doc.Schema.Version, nil
}

func (d decoder) Identify(by []byte) (sbom.FormatID, string) {
	type Document struct {
		Schema model.Schema `json:"schema"`
	}

	var doc Document
	err := json.Unmarshal(by, &doc)
	if err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't proccess it.
		return "", ""
	}

	if !strings.Contains(doc.Schema.URL, "anchore/syft") {
		// not a syft-json document
		return "", ""
	}

	// note: we support all previous schema versions
	return ID, doc.Schema.Version
}

func checkSupportedSchema(documentVersion string, parserVersion string) error {
	documentV, err := semver.NewVersion(documentVersion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	parserV, err := semver.NewVersion(parserVersion)
	if err != nil {
		return fmt.Errorf("error comparing document schema version with parser schema version: %w", err)
	}

	if documentV.GreaterThan(parserV) {
		return fmt.Errorf("document has schema version %s, but parser has older schema version (%s)", documentVersion, parserVersion)
	}

	return nil
}
