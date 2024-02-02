package pkg

// ConanV1LockEntry represents a single "node" entry from a conan.lock V1 file.
type ConanV1LockEntry struct {
	Ref            string    `json:"ref"`
	PackageID      string    `json:"package_id,omitempty"`
	Prev           string    `json:"prev,omitempty"`
	Requires       []string  `json:"requires,omitempty"`
	BuildRequires  []string  `json:"build_requires,omitempty"`
	PythonRequires []string  `json:"py_requires,omitempty"`
	Options        KeyValues `json:"options,omitempty"`
	Path           string    `json:"path,omitempty"`
	Context        string    `json:"context,omitempty"`
}

// ConanV2LockEntry represents a single "node" entry from a conan.lock V2 file.
type ConanV2LockEntry struct {
	Ref             string `json:"ref"`
	PackageID       string `json:"packageID,omitempty"`
	Username        string `json:"username,omitempty"`
	Channel         string `json:"channel,omitempty"`
	RecipeRevision  string `json:"recipeRevision,omitempty"`
	PackageRevision string `json:"packageRevision,omitempty"`
	TimeStamp       string `json:"timestamp,omitempty"`
}

// ConanfileEntry represents a single "Requires" entry from a conanfile.txt.
type ConanfileEntry struct {
	Ref string `mapstructure:"ref" json:"ref"`
}

// ConaninfoEntry represents a single "full_requires" entry from a conaninfo.txt.
type ConaninfoEntry struct {
	Ref       string `json:"ref"`
	PackageID string `json:"package_id,omitempty"`
}
