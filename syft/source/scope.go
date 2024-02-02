package source

import "strings"

// Scope indicates "how" or from "which perspectives" the source object should be cataloged from.
type Scope string

const (
	// UnknownScope is the default scope
	UnknownScope Scope = "unknown-scope"
	// SquashedScope indicates to only catalog content visible from the squashed filesystem representation (what can be seen only within the container at runtime)
	SquashedScope Scope = "squashed"
	// AllLayersScope indicates to catalog content on all layers, regardless if it is visible from the container at runtime.
	AllLayersScope Scope = "all-layers"
)

// AllScopes is a slice containing all possible scope options
var AllScopes = []Scope{
	SquashedScope,
	AllLayersScope,
}

// ParseScope returns a scope as indicated from the given string.
func ParseScope(userStr string) Scope {
	switch strings.ToLower(userStr) {
	case SquashedScope.String():
		return SquashedScope
	case "alllayers", AllLayersScope.String():
		return AllLayersScope
	}
	return UnknownScope
}

func (o Scope) String() string {
	return string(o)
}
