package pkg

type BunLockEntry struct {
	Resolved     string            `mapstructure:"resolved" json:"resolved"`
	Integrity    string            `mapstructure:"integrity" json:"integrity"`
	Dependencies map[string]string `mapstructure:"dependencies" json:"dependencies,omitempty"`
}
