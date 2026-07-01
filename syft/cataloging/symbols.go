package cataloging

import "strings"

// SymbolScope controls which packages get function symbols (from a binary's symbol table) attached to their metadata.
type SymbolScope string

const (
	// SymbolScopeNone disables symbol capture entirely.
	SymbolScopeNone SymbolScope = "none"

	// SymbolScopeStdlib captures symbols only for the synthetic "stdlib" package, leaving module packages without symbols.
	SymbolScopeStdlib SymbolScope = "stdlib"

	// SymbolScopeAll captures symbols for all module packages as well as the synthetic "stdlib" package.
	SymbolScopeAll SymbolScope = "all"
)

// Parse normalizes a SymbolScope, treating an empty (unset) value as SymbolScopeNone. It returns an empty
// SymbolScope to signal an unrecognized value, which callers validate against.
func (s SymbolScope) Parse() SymbolScope {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case string(SymbolScopeAll):
		return SymbolScopeAll
	case string(SymbolScopeStdlib):
		return SymbolScopeStdlib
	case string(SymbolScopeNone), "":
		return SymbolScopeNone
	}
	return ""
}
