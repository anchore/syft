package pkg

type RustCargoLockEntry struct {
	Name         string   `toml:"name" json:"name"`
	Version      string   `toml:"version" json:"version"`
	Source       string   `toml:"source" json:"source"`
	Checksum     string   `toml:"checksum" json:"checksum"`
	Dependencies []string `toml:"dependencies" json:"dependencies"`
}

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
}
