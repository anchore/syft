package syftjson

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct{}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", err
	}

	id, version := d.Identify(reader)
	if version == "" || id != ID {
		return nil, "", "", fmt.Errorf("not a syft-json document")
	}
	var doc model.Document

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", fmt.Errorf("unable to seek to start of Syft JSON SBOM: %+v", err)
	}

	dec := json.NewDecoder(reader)

	if err = dec.Decode(&doc); err != nil {
		return nil, "", "", fmt.Errorf("unable to decode syft-json document: %w", err)
	}

	if err := checkSupportedSchema(doc.Schema.Version, internal.JSONSchemaVersion); err != nil {
		log.Warn(err)
	}

	return toSyftModel(doc), ID, doc.Schema.Version, nil
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	type Document struct {
		Schema model.Schema `json:"schema"`
	}

	dec := json.NewDecoder(r)

	var doc Document
	if err := dec.Decode(&doc); err != nil {
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
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
