package pkg

type DartPubMetadata struct {
	Name      string `mapstructure:"name" json:"name"`
	Version   string `mapstructure:"version" json:"version"`
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`
	VcsURL    string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}
