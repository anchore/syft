package pkg

// CocoaPodfileLockEntry represents a single entry from the "Pods" section of a Podfile.lock file.
type CocoaPodfileLockEntry struct {
	// Checksum is the SHA-1 hash of the podspec file for integrity verification (generated via `pod ipc spec ... | openssl sha1`), ensuring all team members use the same pod specification version
	Checksum string `mapstructure:"checksum" json:"checksum"`

	// ExternalSourceKind is how the pod is resolved when it does not come from a spec repo, taken from the "EXTERNAL SOURCES" section: "path" for a podspec in the working tree, "git" for a repository, "podspec" for a remote podspec. Empty for a pod published to a spec repo.
	ExternalSourceKind string `mapstructure:"externalSourceKind" json:"externalSourceKind,omitempty"`

	// ExternalSourceLocation is the value accompanying the kind: a relative path, repository URL, or podspec URL.
	ExternalSourceLocation string `mapstructure:"externalSourceLocation" json:"externalSourceLocation,omitempty"`
}
