package pkg

// AppleAppBundleEntry represents metadata about an Apple application bundle (CFBundle) extracted from Info.plist files.
// These bundles share the same plist structure across macOS, iOS, watchOS, visionOS, and others.
type AppleAppBundleEntry struct {
	// BundleIdentifier is the unique identifier for the bundle (e.g. "com.apple.Safari")
	BundleIdentifier string `json:"bundleIdentifier,omitempty"`

	// Name is the short name of the bundle
	Name string `json:"name,omitempty"`

	// DisplayName is the user-facing name of the bundle
	DisplayName string `json:"displayName,omitempty"`

	// Executable is the name of the executable within the bundle
	Executable string `json:"executable,omitempty"`

	// ShortVersion is the release (marketing) version of the bundle
	ShortVersion string `json:"shortVersion,omitempty"`

	// Version is the build version of the bundle, which often differs from the short version
	Version string `json:"version,omitempty"`

	// PackageType is the four-letter type code (e.g. "APPL" for apps, "FMWK" for frameworks, "BNDL" for bundles)
	PackageType string `json:"packageType,omitempty"`

	// SupportedPlatforms lists the platforms the bundle targets (e.g. "MacOSX", "iPhoneOS")
	SupportedPlatforms []string `json:"supportedPlatforms,omitempty"`

	// MinimumSystemVersion is the minimum macOS version required to run the bundle
	MinimumSystemVersion string `json:"minimumSystemVersion,omitempty"`

	// MinimumOSVersion is the minimum OS version required for non-macOS platforms (e.g. iOS)
	MinimumOSVersion string `json:"minimumOSVersion,omitempty"`

	// Copyright is the human-readable copyright notice for the bundle
	Copyright string `json:"copyright,omitempty"`

	// PlatformName is the platform name of the SDK used to build the bundle (e.g. "macosx")
	PlatformName string `json:"platformName,omitempty"`

	// SDKName is the name of the SDK used to build the bundle (e.g. "macosx14.0")
	SDKName string `json:"sdkName,omitempty"`
}
