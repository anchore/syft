package golang

import (
	"slices"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
)

// scopePatterns maps a capture-symbols scope onto the go module path globs it selects. The "none" and
// "all" scopes are intentionally absent: both are answered without matching. The "stdlib" scope selects
// no modules at all (the synthetic stdlib package is not a module and is handled separately).
var scopePatterns = map[cataloging.SymbolScope][]string{
	cataloging.SymbolScopeExtendedStdlib: {"golang.org/x/**"},
}

// symbolSelector decides which go module paths get function symbols attached to their metadata. The scope
// preset and any user-supplied include patterns are compiled into a single glob list so there is exactly
// one matcher answering "does this module path get symbols" (two matchers over the same subject drift).
type symbolSelector struct {
	scope    cataloging.SymbolScope
	patterns []string
}

func newSymbolSelector(scope cataloging.SymbolScope, include []string) symbolSelector {
	// normalize here rather than trusting the caller: the CLI runs Parse in PostLoad, but a library
	// consumer setting CaptureSymbols directly (or via WithCaptureSymbols) does not, and an unnormalized
	// value falls through both switches below into stdlib-only capture rather than the intended scope.
	scope = scope.Parse()

	var patterns []string
	for _, pattern := range slices.Concat(scopePatterns[scope], include) {
		if !doublestar.ValidatePattern(pattern) {
			// a typo in a filter that decides what gets vulnerability-scanned must not pass quietly:
			// someone would believe they captured symbols they did not. Drop just this pattern and keep
			// the rest of the selection in force.
			log.WithFields("pattern", pattern).Warn("ignoring malformed golang capture-symbols-include pattern")
			continue
		}
		patterns = append(patterns, pattern)
	}
	return symbolSelector{scope: scope, patterns: patterns}
}

// enabled reports whether symbols should be extracted from the binary at all.
func (s symbolSelector) enabled() bool {
	return s.scope != cataloging.SymbolScopeNone
}

// selects reports whether the given go module path gets symbols. The binary's own main module is treated
// exactly like a dependency.
func (s symbolSelector) selects(modulePath string) bool {
	switch s.scope {
	case cataloging.SymbolScopeNone:
		return false
	case cataloging.SymbolScopeAll:
		return true
	}
	for _, pattern := range s.patterns {
		matched, err := doublestar.Match(pattern, modulePath)
		if err != nil {
			// unreachable: newSymbolSelector rejects (and warns about) patterns that cannot compile
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// filter drops the entries of a module-path-keyed symbol map that the selector does not select. It returns
// nil when nothing is selected so callers attach no symbols map at all (rather than an empty one, which
// would defeat the omitempty JSON tag).
func (s symbolSelector) filter(byModule map[string]map[string][]string) map[string]map[string][]string {
	switch s.scope {
	case cataloging.SymbolScopeNone:
		return nil
	case cataloging.SymbolScopeAll:
		return byModule
	}
	for modulePath := range byModule {
		if !s.selects(modulePath) {
			delete(byModule, modulePath)
		}
	}
	if len(byModule) == 0 {
		return nil
	}
	return byModule
}
