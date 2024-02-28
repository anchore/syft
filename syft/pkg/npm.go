package pkg

// NpmPackage represents the contents of a javascript package.json file.
type NpmPackage struct {
	Name        string `mapstructure:"name" json:"name"`
	Version     string `mapstructure:"version" json:"version"`
	Author      string `mapstructure:"author" json:"author"`
	Homepage    string `mapstructure:"homepage" json:"homepage"`
	Description string `mapstructure:"description" json:"description"`
	URL         string `mapstructure:"url" json:"url"`
	Private     bool   `mapstructure:"private" json:"private"`
}

// NpmPackageLockEntry represents a single entry within the "packages" section of a package-lock.json file.
type NpmPackageLockEntry struct {
	Resolved  string `mapstructure:"resolved" json:"resolved"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}

// YarnLockEntry represents a single entry section of a yarn.lock file.
type YarnLockEntry struct {
	Resolved  string `mapstructure:"resolved" json:"resolved"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}
