package pkg

import "strings"

type RustCargo struct {
	CargoEntry *RustCargoEntry     `json:"cargoEntry,omitempty"`
	LockEntry  *RustCargoLockEntry `json:"lockEntry,omitempty"`
}

type RustCargoEntry struct {
	DownloadURL    string `json:"downloadURL,omitempty"`
	DownloadDigest string `json:"downloadDigest,omitempty"`
	Description    string `json:"description"`
	Homepage       string `json:"homepage"`
	Repository     string `json:"repository"`
}

type RustCargoLockEntry struct {
	CargoLockVersion int      `toml:"-" json:"cargoLockVersion,omitempty"`
	Name             string   `toml:"name" json:"name"`
	Version          string   `toml:"version" json:"version"`
	Source           string   `toml:"source" json:"source"`
	Checksum         string   `toml:"checksum" json:"checksum"`
	Dependencies     []string `toml:"dependencies" json:"dependencies,omitempty"`
}

// SourceRemoteURL returns the remote URL based on the Source field of the RustCargoLockEntry. The second return value
// is true if the Source field represents a remote URL.
func (r RustCargoLockEntry) SourceRemoteURL() (string, bool) {
	before, after, found := strings.Cut(r.Source, "+")
	if !found {
		return "", false
	}

	// see https://github.com/rust-lang/cargo/blob/master/crates/cargo-util-schemas/src/core/source_kind.rs
	return after, before != "local-registry"
}

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
}
