package packages

import "strings"

const (
	UnknownPresenterOption      PresenterOption = "UnknownPresenterOption"
	JSONPresenterOption         PresenterOption = "json"
	TextPresenterOption         PresenterOption = "text"
	TablePresenterOption        PresenterOption = "table"
	CycloneDxPresenterOption    PresenterOption = "cyclonedx"
	SPDXTagValuePresenterOption PresenterOption = "spdx-tag-value"
	SPDXJSONPresenterOption     PresenterOption = "spdx-json"
)

var AllPresenters = []PresenterOption{
	JSONPresenterOption,
	TextPresenterOption,
	TablePresenterOption,
	CycloneDxPresenterOption,
	SPDXTagValuePresenterOption,
	SPDXJSONPresenterOption,
}

type PresenterOption string

func ParsePresenterOption(userStr string) PresenterOption {
	switch strings.ToLower(userStr) {
	case string(JSONPresenterOption):
		return JSONPresenterOption
	case string(TextPresenterOption):
		return TextPresenterOption
	case string(TablePresenterOption):
		return TablePresenterOption
	case string(CycloneDxPresenterOption), "cyclone", "cyclone-dx":
		return CycloneDxPresenterOption
	case string(SPDXTagValuePresenterOption), "spdx-tagvalue", "spdxtagvalue", "spdx-tv":
		return SPDXTagValuePresenterOption
	case string(SPDXJSONPresenterOption), "spdxjson":
		return SPDXJSONPresenterOption
	default:
		return UnknownPresenterOption
	}
}
