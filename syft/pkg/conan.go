package pkg

type ConanV2LockEntry struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	Username        string `json:"username,omitempty"`
	Channel         string `json:"channel,omitempty"`
	RecipeRevision  string `json:"recipe_revision,omitempty"`
	PackageID       string `json:"package_id,omitempty"`
	PackageRevision string `json:"package_revision,omitempty"`
	TimeStamp       string `json:"timestamp,omitempty"`
	Ref             string `json:"ref"`
}

// ConanV1LockEntry represents a single "node" entry from a conan.lock file.
type ConanV1LockEntry struct {
	Ref            string            `json:"ref"`
	PackageID      string            `json:"package_id,omitempty"`
	Prev           string            `json:"prev,omitempty"`
	Requires       []string          `json:"requires,omitempty"`
	BuildRequires  []string          `json:"build_requires,omitempty"`
	PythonRequires []string          `json:"py_requires,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	Path           string            `json:"path,omitempty"`
	Context        string            `json:"context,omitempty"`
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
