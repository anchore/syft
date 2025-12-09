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
		switch scope {
		case SymbolScopeNone:
			// explicit "none" means don't capture (but continue checking other scopes)
			continue
		case SymbolScopeAll:
			return true
		case SymbolScopeLibraries:
			if data.HasExports {
				return true
			}
		case SymbolScopeApplications:
			if data.HasEntrypoint {
				return true
			}
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
