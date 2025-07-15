package pkg

// DartPubspecLockEntry is a struct that represents a single entry found in the "packages" section in a Dart pubspec.lock file.
type DartPubspecLockEntry struct {
	Name      string `mapstructure:"name" json:"name"`
	Version   string `mapstructure:"version" json:"version"`
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`
	VcsURL    string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}

// DartPubspec is a struct that represents a package described in a pubspec.yaml file
type DartPubspec struct {
	Homepage          string                  `mapstructure:"homepage" json:"homepage,omitempty"`
	Repository        string                  `mapstructure:"repository" json:"repository,omitempty"`
	Documentation     string                  `mapstructure:"documentation" json:"documentation,omitempty"`
	PublishTo         string                  `mapstructure:"publish_to" json:"publish_to,omitempty"`
	Environment       *DartPubspecEnvironment `mapstructure:"environment" json:"environment,omitempty"`
	Platforms         []string                `mapstructure:"platforms" json:"platforms,omitempty"`
	IgnoredAdvisories []string                `mapstructure:"ignored_advisories" json:"ignored_advisories,omitempty"`
}

type DartPubspecEnvironment struct {
	SDK     string `mapstructure:"sdk" json:"sdk,omitempty"`
	Flutter string `mapstructure:"flutter" json:"flutter,omitempty"`
}
