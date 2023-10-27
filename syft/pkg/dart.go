package pkg

// DartPubspecLockEntry is a struct that represents a single entry found in the "packages" section in a Dart pubspec.lock file.
type DartPubspecLockEntry struct {
	Name      string `mapstructure:"name" json:"name"`
	Version   string `mapstructure:"version" json:"version"`
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`
	VcsURL    string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}
