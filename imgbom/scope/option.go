package scope

import "strings"

const (
	UnknownScope Option = iota
	SquashedScope
	AllLayersScope
)

type Option uint

var optionStr = []string{
	"UnknownScope",
	"Squashed",
	"AllLayers",
}

var Options = []Option{
	SquashedScope,
	AllLayersScope,
}

func ParseOption(userStr string) Option {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SquashedScope.String()):
		return SquashedScope
	case strings.ToLower(AllLayersScope.String()):
		return AllLayersScope
	}
	return UnknownScope
}

func (o Option) String() string {
	if int(o) >= len(optionStr) {
		return optionStr[0]
	}

	return optionStr[o]
}
