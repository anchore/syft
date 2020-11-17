package source

import "strings"

// Scope indicates "how" or from "which perspectives" the source object should be cataloged from.
type Scope string

const (
	// UnknownScope is the default scope
	UnknownScope Scope = "UnknownScope"
	// SquashedScope indicates to only catalog content visible from the squashed filesystem representation (what can be seen only within the container at runtime)
	SquashedScope Scope = "Squashed"
	// AllLayersScope indicates to catalog content on all layers, irregardless if it is visible from the container at runtime.
	AllLayersScope Scope = "AllLayers"
)

// AllScopes is a slice containing all possible scope options
var AllScopes = []Scope{
	SquashedScope,
	AllLayersScope,
}

// ParseScope returns a scope as indicated from the given string.
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
