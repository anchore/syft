package pkg

// CocoaPodfileLockEntry represents a single entry from the "Pods" section of a Podfile.lock file.
type CocoaPodfileLockEntry struct {
	Checksum string `mapstructure:"checksum" json:"checksum"`
}
