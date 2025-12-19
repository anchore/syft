package pkg

// MacOSAppEntry represents metadata about a macOS application extracted from Info.plist files.
type MacOSAppEntry struct {
	// BundleIdentifier is the unique identifier for the application (e.g. "com.apple.Safari")
	BundleIdentifier string `json:"bundleIdentifier,omitempty"`
}
