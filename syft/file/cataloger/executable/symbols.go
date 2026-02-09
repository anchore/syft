package executable

import "github.com/anchore/syft/syft/file"

// shouldCaptureSymbols determines whether symbols should be captured for the given executable
// based on the configured capture scopes. If any configured scope matches the executable's
// characteristics, symbols will be captured.
func shouldCaptureSymbols(data *file.Executable, cfg SymbolConfig) bool {
	if data == nil {
		return false
	}

	for _, scope := range cfg.CaptureScope {
		switch scope { //nolint:gocritic  // lets elect a pattern as if we'll have multiple options in the future...
		case SymbolScopeGolang:
			if hasGolangToolchain(data) {
				return true
			}
		}
	}

	// if no scopes matched, do not capture symbols (empty scope means none)
	return false
}

// hasGolangToolchain checks if the executable was built with the Go toolchain.
func hasGolangToolchain(data *file.Executable) bool {
	for _, tc := range data.Toolchains {
		if tc.Name == "go" {
			return true
		}
	}
	return false
}
