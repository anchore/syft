package source

import "strings"

type Scope string

const (
	UnknownScope   Scope = "UnknownScope"
	SquashedScope  Scope = "Squashed"
	AllLayersScope Scope = "AllLayers"
)

var AllScopes = []Scope{
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
	return string(o)
}
