package pkg

type DenoLockEntry struct {
	Integrity    string   `mapstructure:"integrity" json:"integrity"`
	Dependencies []string `mapstructure:"dependencies" json:"dependencies"`
}

type DenoRemoteLockEntry struct {
	URL       string `mapstructure:"url" json:"url"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}
