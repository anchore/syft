package pkg

// AppleAppBundleEntry represents metadata about an Apple application bundle (CFBundle) extracted from Info.plist files.
// These bundles share the same plist structure across macOS, iOS, watchOS, visionOS, and others.
type AppleAppBundleEntry struct {
	// BundleIdentifier is the unique identifier for the application (e.g. "com.apple.Safari")
	BundleIdentifier string `json:"bundleIdentifier,omitempty"`
}
