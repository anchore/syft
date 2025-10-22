package pkg

// CocoaPodfileLockEntry represents a single entry from the "Pods" section of a Podfile.lock file.
type CocoaPodfileLockEntry struct {
	// Checksum is the SHA-1 hash of the podspec file for integrity verification (generated via `pod ipc spec ... | openssl sha1`), ensuring all team members use the same pod specification version
	Checksum string `mapstructure:"checksum" json:"checksum"`
}
