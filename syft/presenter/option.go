package presenter

import "strings"

const (
	UnknownPresenter   Option = "UnknownPresenter"
	JSONPresenter      Option = "json"
	TextPresenter      Option = "text"
	TablePresenter     Option = "table"
	CycloneDxPresenter Option = "cyclonedx"
)

var Options = []Option{
	JSONPresenter,
	TextPresenter,
	TablePresenter,
	CycloneDxPresenter,
}

type Option string

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case string(JSONPresenter):
		return JSONPresenter
	case string(TextPresenter):
		return TextPresenter
	case string(TablePresenter):
		return TablePresenter
	case string(CycloneDxPresenter), "cyclone", "cyclone-dx":
		return CycloneDxPresenter
	default:
		return UnknownPresenter
	}
}
