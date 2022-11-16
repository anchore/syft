package formats

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/github"
	"github.com/anchore/syft/syft/formats/spdx22json"
	"github.com/anchore/syft/syft/formats/spdx22tagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

func Formats() []sbom.Format {
	return []sbom.Format{
		syftjson.Format(),
		cyclonedxxml.Format(),
		cyclonedxjson.Format(),
		github.Format(),
		spdx22tagvalue.Format(),
		spdx22json.Format(),
		table.Format(),
		text.Format(),
		template.Format(),
	}
}

func Identify(by []byte) sbom.Format {
	for _, f := range Formats() {
		if err := f.Validate(bytes.NewReader(by)); err != nil {
			continue
		}
		return f
	}
	return nil
}

func ByName(name string) sbom.Format {
	cleanName := cleanFormatName(name)
	for _, f := range Formats() {
		if cleanFormatName(string(f.ID())) == cleanName {
			return f
		}
	}

	// handle any aliases for any supported format
	switch cleanName {
	case "json", "syftjson":
		return ByID(syftjson.ID)
	case "cyclonedx", "cyclone", "cyclonedxxml":
		return ByID(cyclonedxxml.ID)
	case "cyclonedxjson":
		return ByID(cyclonedxjson.ID)
	case "github", "githubjson":
		return ByID(github.ID)
	case "spdx", "spdxtv", "spdxtagvalue":
		return ByID(spdx22tagvalue.ID)
	case "spdxjson":
		return ByID(spdx22json.ID)
	case "table":
		return ByID(table.ID)
	case "text":
		return ByID(text.ID)
	case "template":
		ByID(template.ID)
	}

	return nil
}

func IDs() (ids []sbom.FormatID) {
	for _, f := range Formats() {
		ids = append(ids, f.ID())
	}
	return ids
}

func ByID(id sbom.FormatID) sbom.Format {
	for _, f := range Formats() {
		if f.ID() == id {
			return f
		}
	}
	return nil
}

func cleanFormatName(name string) string {
	r := strings.NewReplacer("-", "", "_", "")
	return strings.ToLower(r.Replace(name))
}

// Encode takes all SBOM elements and a format option and encodes an SBOM document.
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}

// Decode takes a reader for an SBOM and generates all internal SBOM elements.
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
	}

	f := Identify(by)
	if f == nil {
		return nil, nil, fmt.Errorf("unable to identify format")
	}

	s, err := f.Decode(bytes.NewReader(by))
	return s, f, err
}
