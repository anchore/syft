package pkg

// DartPubspecLockEntry is a struct that represents a single entry found in the "packages" section in a Dart pubspec.lock file.
type DartPubspecLockEntry struct {
	// Name is the package name as found in the pubspec.lock file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the pubspec.lock file
	Version string `mapstructure:"version" json:"version"`

	// HostedURL is the URL of the package repository for hosted packages (typically pub.dev, but can be custom repository identified by hosted-url). When PUB_HOSTED_URL environment variable changes, lockfile tracks the source.
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`

	// VcsURL is the URL of the VCS repository for git/path dependencies (for packages fetched from version control systems like Git)
	VcsURL string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}

// DartPubspec is a struct that represents a package described in a pubspec.yaml file
type DartPubspec struct {
	// Homepage is the package homepage URL
	Homepage string `mapstructure:"homepage" json:"homepage,omitempty"`

	// Repository is the source code repository URL
	Repository string `mapstructure:"repository" json:"repository,omitempty"`

	// Documentation is the documentation site URL
	Documentation string `mapstructure:"documentation" json:"documentation,omitempty"`

	// PublishTo is the package repository to publish to, or "none" to prevent accidental publishing
	PublishTo string `mapstructure:"publish_to" json:"publish_to,omitempty"`

	// Environment is SDK version constraints for Dart and Flutter
	Environment *DartPubspecEnvironment `mapstructure:"environment" json:"environment,omitempty"`

	// Platforms are the supported platforms (Android, iOS, web, etc.)
	Platforms []string `mapstructure:"platforms" json:"platforms,omitempty"`

	// IgnoredAdvisories are the security advisories to explicitly ignore for this package
	IgnoredAdvisories []string `mapstructure:"ignored_advisories" json:"ignored_advisories,omitempty"`
}

// DartPubspecEnvironment represents SDK version constraints from the environment section of pubspec.yaml.
type DartPubspecEnvironment struct {
	// SDK is the Dart SDK version constraint (e.g. ">=2.12.0 <3.0.0")
	SDK string `mapstructure:"sdk" json:"sdk,omitempty"`

	// Flutter is the Flutter SDK version constraint if this is a Flutter package
	Flutter string `mapstructure:"flutter" json:"flutter,omitempty"`
}
