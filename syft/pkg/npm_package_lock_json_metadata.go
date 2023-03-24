package pkg

// NpmPackageLockJSONMetadata holds parsing information for a javascript package-lock.json file
type NpmPackageLockJSONMetadata struct {
	Resolved  string `mapstructure:"resolved" json:"resolved"`
	Integrity string `mapstructure:"integrity" json:"integrity"`
}
