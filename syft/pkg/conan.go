package pkg

// ConanV1LockEntry represents a single "node" entry from a conan.lock V1 file.
type ConanV1LockEntry struct {
	// Ref is the package reference string in format name/version@user/channel
	Ref string `json:"ref"`

	// PackageID is a unique package variant identifier computed from settings/options (static hash in Conan 1.x, can have collisions with complex dependency graphs)
	PackageID string `json:"package_id,omitempty"`

	// Prev is the previous lock entry reference for versioning
	Prev string `json:"prev,omitempty"`

	// Requires are the runtime package dependencies
	Requires []string `json:"requires,omitempty"`

	// BuildRequires are the build-time dependencies (e.g. cmake, compilers)
	BuildRequires []string `json:"build_requires,omitempty"`

	// PythonRequires are the Python dependencies needed for Conan recipes
	PythonRequires []string `json:"py_requires,omitempty"`

	// Options are package configuration options as key-value pairs (e.g. shared=True, fPIC=True)
	Options KeyValues `json:"options,omitempty"`

	// Path is the filesystem path to the package in Conan cache
	Path string `json:"path,omitempty"`

	// Context is the build context information
	Context string `json:"context,omitempty"`
}

// ConanV2LockEntry represents a single "node" entry from a conan.lock V2 file.
type ConanV2LockEntry struct {
	// Ref is the package reference string in format name/version@user/channel
	Ref string `json:"ref"`

	// PackageID is a unique package variant identifier (dynamic in Conan 2.0, more accurate than V1)
	PackageID string `json:"packageID,omitempty"`

	// Username is the Conan user/organization name
	Username string `json:"username,omitempty"`

	// Channel is the Conan channel name indicating stability/purpose (e.g. stable, testing, experimental)
	Channel string `json:"channel,omitempty"`

	// RecipeRevision is a git-like revision hash (RREV) of the recipe
	RecipeRevision string `json:"recipeRevision,omitempty"`

	// PackageRevision is a git-like revision hash of the built binary package
	PackageRevision string `json:"packageRevision,omitempty"`

	// TimeStamp is when this package was built/locked
	TimeStamp string `json:"timestamp,omitempty"`
}

// ConanfileEntry represents a single "Requires" entry from a conanfile.txt.
type ConanfileEntry struct {
	// Ref is the package reference string in format name/version@user/channel
	Ref string `mapstructure:"ref" json:"ref"`
}

// ConaninfoEntry represents a single "full_requires" entry from a conaninfo.txt.
type ConaninfoEntry struct {
	// Ref is the package reference string in format name/version@user/channel
	Ref string `json:"ref"`

	// PackageID is a unique package variant identifier
	PackageID string `json:"package_id,omitempty"`
}
