package syft

import (
	"bytes"
	"strings"

	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/github"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

// these have been exported for the benefit of API users
const (
	JSONFormatID          = syftjson.ID
	TextFormatID          = text.ID
	TableFormatID         = table.ID
	CycloneDxXMLFormatID  = cyclonedxxml.ID
	CycloneDxJSONFormatID = cyclonedxjson.ID
	GitHubID              = github.ID
	SPDXTagValueFormatID  = spdx22tagvalue.ID
	SPDXJSONFormatID      = spdx22json.ID
)

var formats []sbom.Format

func init() {
	formats = []sbom.Format{
		syftjson.Format(),
		cyclonedxxml.Format(),
		cyclonedxjson.Format(),
		github.Format(),
		spdx22tagvalue.Format(),
		spdx22json.Format(),
		table.Format(),
		text.Format(),
	}
}

func FormatIDs() (ids []sbom.FormatID) {
	for _, f := range formats {
		ids = append(ids, f.ID())
	}
	return ids
}

func FormatByID(id sbom.FormatID) sbom.Format {
	for _, f := range formats {
		if f.ID() == id {
			return f
		}
	}
	return nil
}

func FormatByName(name string) sbom.Format {
	cleanName := cleanFormatName(name)
	for _, f := range formats {
		if cleanFormatName(string(f.ID())) == cleanName {
			return f
		}
	}

	// handle any aliases for any supported format
	switch cleanName {
	case "json", "syftjson":
		return FormatByID(syftjson.ID)
	case "cyclonedx", "cyclone", "cyclonedxxml":
		return FormatByID(cyclonedxxml.ID)
	case "cyclonedxjson":
		return FormatByID(cyclonedxjson.ID)
	case "github", "githubjson":
		return FormatByID(github.ID)
	case "spdx", "spdxtv", "spdxtagvalue":
		return FormatByID(spdx22tagvalue.ID)
	case "spdxjson":
		return FormatByID(spdx22json.ID)
	case "table":
		return FormatByID(table.ID)
	case "text":
		return FormatByID(text.ID)
	}

	return nil
}

func cleanFormatName(name string) string {
	r := strings.NewReplacer("-", "", "_", "")
	return strings.ToLower(r.Replace(name))
}

func IdentifyFormat(by []byte) sbom.Format {
	for _, f := range formats {
		if err := f.Validate(bytes.NewReader(by)); err != nil {
			continue
		}
		return f
	}
	return nil
}
