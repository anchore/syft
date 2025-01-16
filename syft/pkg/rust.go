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

type RustCratesEnrichedEntry struct {
	Name             string `toml:"name" json:"name"`
	Version          string `toml:"version" json:"version"`
	Source           string `toml:"source" json:"source"`
	Description      string `json:"description"`
	Homepage         string `json:"homepage"`
	Supplier         string `json:"supplier"`
	DownloadLocation string `json:"downloadLocation"`
	Repository       string `json:"repository"`
	LicenseInfo      string `json:"licenseInfo"`
	ReleaseTime      string `json:"releaseTime"`
	Summary          string `json:"summary"`
	CreatedBy        string `json:"createdBy"`
}
