package pkg

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
}

// RustCargoLockEntry Required for packagemeta.TestAllNames
type RustCargoLockEntry struct{}
