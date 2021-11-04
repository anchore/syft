package format

import "strings"

const (
	UnknownFormatOption Option = "UnknownFormatOption"
	JSONOption          Option = "json"
	TextOption          Option = "text"
	TableOption         Option = "table"
	CycloneDxOption     Option = "cyclonedx"
	SPDXTagValueOption  Option = "spdx-tag-value"
	SPDXJSONOption      Option = "spdx-json"
)

var AllOptions = []Option{
	JSONOption,
	TextOption,
	TableOption,
	CycloneDxOption,
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
	case string(CycloneDxOption), "cyclone", "cyclone-dx":
		return CycloneDxOption
	case string(SPDXTagValueOption), "spdx", "spdx-tagvalue", "spdxtagvalue", "spdx-tv", "spdxtv":
		return SPDXTagValueOption
	case string(SPDXJSONOption), "spdxjson":
		return SPDXJSONOption
	default:
		return UnknownFormatOption
	}
}
