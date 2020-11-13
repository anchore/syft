package source

import "strings"

const (
	UnknownScope Scope = iota
	SquashedScope
	AllLayersScope
)

type Scope int

var optionStr = []string{
	"UnknownScope",
	"Squashed",
	"AllLayers",
}

var Options = []Scope{
	SquashedScope,
	AllLayersScope,
}

func ParseScope(userStr string) Scope {
	switch strings.ToLower(userStr) {
	case strings.ToLower(SquashedScope.String()):
		return SquashedScope
	case "all-layers", strings.ToLower(AllLayersScope.String()):
		return AllLayersScope
	}
	return UnknownScope
}

func (o Scope) String() string {
	if int(o) >= len(optionStr) || o < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}
