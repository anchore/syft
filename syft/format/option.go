package format

import "strings"

const (
	UnknownFormatOption Option = "UnknownFormatOption"
	JSONOption          Option = "json"
	TextOption          Option = "text"
	TableOption         Option = "table"
	CycloneDxXMLOption  Option = "cyclonedx"
	CycloneDxJSONOption Option = "cyclonedx-json"
	GitHubJSON          Option = "github"
	SPDXTagValueOption  Option = "spdx-tag-value"
	SPDXJSONOption      Option = "spdx-json"
)

var AllOptions = []Option{
	JSONOption,
	TextOption,
	TableOption,
	CycloneDxXMLOption,
	CycloneDxJSONOption,
	GitHubJSON,
	SPDXTagValueOption,
	SPDXJSONOption,
}

type Option string

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case string(JSONOption):
		return JSONOption
	case string(TextOption):
		return TextOption
	case string(TableOption):
		return TableOption
	case string(CycloneDxXMLOption), "cyclone", "cyclone-dx", "cyclone-dx-xml", "cyclone-xml":
		// NOTE(jonasagx): setting "cyclone" to XML by default for retro-compatibility.
		// If we want to show no preference between XML and JSON please remove it.
		return CycloneDxXMLOption
	case string(CycloneDxJSONOption), "cyclone-json", "cyclone-dx-json":
		return CycloneDxJSONOption
	case string(GitHubJSON):
		return GitHubJSON
	case string(SPDXTagValueOption), "spdx", "spdx-tagvalue", "spdxtagvalue", "spdx-tv", "spdxtv":
		return SPDXTagValueOption
	case string(SPDXJSONOption), "spdxjson":
		return SPDXJSONOption
	default:
		return UnknownFormatOption
	}
}
