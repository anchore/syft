package packages

import "strings"

const (
	UnknownPresenterOption   PresenterOption = "UnknownPresenterOption"
	JSONPresenterOption      PresenterOption = "json"
	TextPresenterOption      PresenterOption = "text"
	TablePresenterOption     PresenterOption = "table"
	CycloneDxPresenterOption PresenterOption = "cyclonedx"
	SPDXPresenterOption      PresenterOption = "spdx"
)

var AllPresenters = []PresenterOption{
	JSONPresenterOption,
	TextPresenterOption,
	TablePresenterOption,
	CycloneDxPresenterOption,
	SPDXPresenterOption,
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
	case string(SPDXPresenterOption):
		return SPDXPresenterOption
	default:
		return UnknownPresenterOption
	}
}
