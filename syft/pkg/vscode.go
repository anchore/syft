package pkg

// VscodeExtensionEntry describes a single Visual Studio Code extension as it
// appears in the user-extensions registry file
// (typically ~/.vscode/extensions/extensions.json on Linux/macOS or
// %USERPROFILE%\.vscode\extensions\extensions.json on Windows).
//
// Extensions installed from the Marketplace are recorded with publisher,
// extension name, version, and a marketplace UUID. The cataloger uses the
// `<publisher>.<name>` form for Pkg.Name to match how the extension is
// canonically referenced in CLI / settings.json (`code --install-extension <id>`).
type VscodeExtensionEntry struct {
	// Publisher is the marketplace publisher namespace, e.g. "github" in
	// "github.copilot-chat".
	Publisher string `mapstructure:"publisher" json:"publisher"`

	// PublisherDisplayName is the human-readable publisher name reported by
	// the marketplace at install time, e.g. "GitHub".
	PublisherDisplayName string `mapstructure:"publisherDisplayName" json:"publisherDisplayName,omitempty"`

	// UUID is the marketplace UUID assigned to the extension. May be empty
	// for extensions not installed from the marketplace (sideloaded VSIXs,
	// builtin extensions packaged with VSCode).
	UUID string `mapstructure:"uuid" json:"uuid,omitempty"`

	// IsBuiltin is true for extensions shipped with VSCode itself rather than
	// installed by the user from the marketplace.
	IsBuiltin bool `mapstructure:"isBuiltin" json:"isBuiltin,omitempty"`

	// IsPreReleaseVersion is true when the installed version is the
	// publisher's prerelease channel.
	IsPreReleaseVersion bool `mapstructure:"isPreReleaseVersion" json:"isPreReleaseVersion,omitempty"`

	// TargetPlatform is the marketplace target-platform tag (e.g.
	// "linux-x64", "darwin-arm64", or "undefined" for cross-platform).
	TargetPlatform string `mapstructure:"targetPlatform" json:"targetPlatform,omitempty"`
}
