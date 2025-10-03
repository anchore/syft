package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ FileOwner = (*PythonPackage)(nil)

// PythonPackage represents all captured data for a python egg or wheel package (specifically as outlined in
// the PyPA core metadata specification https://packaging.python.org/en/latest/specifications/core-metadata/).
// Historically these were defined in PEPs 345, 314, and 241, but have been superseded by PEP 566. This means that this
// struct can (partially) express at least versions 1.0, 1.1, 1.2, 2.1, 2.2, and 2.3 of the metadata format.
type PythonPackage struct {
	// Name is the package name from the Name field in PKG-INFO or METADATA.
	Name string `json:"name" mapstructure:"Name"`
	// Version is the package version from the Version field in PKG-INFO or METADATA.
	Version string `json:"version" mapstructure:"Version"`
	// Author is the package author name from the Author field.
	Author string `json:"author" mapstructure:"Author"`
	// AuthorEmail is the package author's email address from the Author-Email field.
	AuthorEmail string `json:"authorEmail" mapstructure:"AuthorEmail"`
	// Platform indicates the target platform for the package (e.g., "any", "linux", "win32").
	Platform string `json:"platform" mapstructure:"Platform"`
	// Files are the installed files listed in the RECORD file for wheels or installed-files.txt for eggs.
	Files []PythonFileRecord `json:"files,omitempty"`
	// SitePackagesRootPath is the root directory path containing the package (e.g., "/usr/lib/python3.9/site-packages").
	SitePackagesRootPath string `json:"sitePackagesRootPath"`
	// TopLevelPackages are the top-level Python module names from top_level.txt file.
	TopLevelPackages []string `json:"topLevelPackages,omitempty"`
	// DirectURLOrigin contains VCS or direct URL installation information from direct_url.json.
	DirectURLOrigin *PythonDirectURLOriginInfo `json:"directUrlOrigin,omitempty"`
	// RequiresPython specifies the Python version requirement (e.g., ">=3.6").
	RequiresPython string `json:"requiresPython,omitempty" mapstructure:"RequiresPython"`
	// RequiresDist lists the package dependencies with version specifiers from Requires-Dist fields.
	RequiresDist []string `json:"requiresDist,omitempty" mapstructure:"RequiresDist"`
	// ProvidesExtra lists optional feature names that can be installed via extras (e.g., "dev", "test").
	ProvidesExtra []string `json:"providesExtra,omitempty" mapstructure:"ProvidesExtra"`
}

// PythonFileDigest represents the file metadata for a single file attributed to a python package.
type PythonFileDigest struct {
	// Algorithm is the hash algorithm used (e.g., "sha256").
	Algorithm string `json:"algorithm"`
	// Value is the hex-encoded hash digest value.
	Value string `json:"value"`
}

// PythonFileRecord represents a single entry within a RECORD file for a python wheel or egg package
type PythonFileRecord struct {
	// Path is the installed file path from the RECORD file.
	Path string `json:"path"`
	// Digest contains the hash algorithm and value for file integrity verification.
	Digest *PythonFileDigest `json:"digest,omitempty"`
	// Size is the file size in bytes as a string.
	Size string `json:"size,omitempty"`
}

// PythonDirectURLOriginInfo represents installation source metadata from direct_url.json for packages installed from VCS or direct URLs.
type PythonDirectURLOriginInfo struct {
	// URL is the source URL from which the package was installed.
	URL string `json:"url"`
	// CommitID is the VCS commit hash if installed from version control.
	CommitID string `json:"commitId,omitempty"`
	// VCS is the version control system type (e.g., "git", "hg").
	VCS string `json:"vcs,omitempty"`
}

func (m PythonPackage) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}

// PythonPipfileLockEntry represents a single package entry within a Pipfile.lock file.
type PythonPipfileLockEntry struct {
	// Hashes are the package file hash values in the format "algorithm:digest" for integrity verification.
	Hashes []string `mapstructure:"hashes" json:"hashes"`
	// Index is the PyPI index name where the package should be fetched from.
	Index string `mapstructure:"index" json:"index"`
}

// PythonPoetryLockEntry represents a single package entry within a Pipfile.lock file.
type PythonPoetryLockEntry struct {
	// Index is the package repository name where the package should be fetched from.
	Index string `mapstructure:"index" json:"index"`
	// Dependencies are the package's runtime dependencies with version constraints.
	Dependencies []PythonPoetryLockDependencyEntry `json:"dependencies"`
	// Extras are optional feature groups that include additional dependencies.
	Extras []PythonPoetryLockExtraEntry `json:"extras,omitempty"`
}

// PythonPoetryLockDependencyEntry represents a single dependency entry within a Poetry lock file.
type PythonPoetryLockDependencyEntry struct {
	// Name is the dependency package name.
	Name string `json:"name"`
	// Version is the locked version or version constraint for the dependency.
	Version string `json:"version"`
	// Optional indicates whether this dependency is optional (only needed for certain extras).
	Optional bool `json:"optional"`
	// Markers are environment marker expressions that conditionally enable the dependency (e.g., "python_version >= '3.8'").
	Markers string `json:"markers,omitempty"`
	// Extras are the optional feature names from the dependency that should be installed.
	Extras []string `json:"extras,omitempty"`
}

// PythonPoetryLockExtraEntry represents an optional feature group in a Poetry lock file.
type PythonPoetryLockExtraEntry struct {
	// Name is the optional feature name (e.g., "dev", "test").
	Name string `json:"name"`
	// Dependencies are the package names required when this extra is installed.
	Dependencies []string `json:"dependencies"`
}

// PythonRequirementsEntry represents a single entry within a [*-]requirements.txt file.
type PythonRequirementsEntry struct {
	// Name is the package name from the requirements file.
	Name string `json:"name" mapstructure:"Name"`
	// Extras are the optional features to install from the package (e.g., package[dev,test]).
	Extras []string `json:"extras,omitempty" mapstructure:"Extras"`
	// VersionConstraint specifies version requirements (e.g., ">=1.0,<2.0").
	VersionConstraint string `json:"versionConstraint" mapstructure:"VersionConstraint"`
	// URL is the direct download URL or VCS URL if specified instead of a PyPI package.
	URL string `json:"url,omitempty" mapstructure:"URL"`
	// Markers are environment marker expressions for conditional installation (e.g., "python_version >= '3.8'").
	Markers string `json:"markers,omitempty" mapstructure:"Markers"`
}

// PythonUvLockDependencyEntry represents a single dependency entry within a uv lock file.
type PythonUvLockDependencyEntry struct {
	// Name is the dependency package name.
	Name string `json:"name"`
	// Optional indicates whether this dependency is optional (only needed for certain extras).
	Optional bool `json:"optional"`
	// Markers are environment marker expressions that conditionally enable the dependency (e.g., "python_version >= '3.8'").
	Markers string `json:"markers,omitempty"`
	// Extras are the optional feature names from the dependency that should be installed.
	Extras []string `json:"extras,omitempty"`
}

// PythonUvLockExtraEntry represents an optional feature group in a uv lock file.
type PythonUvLockExtraEntry struct {
	// Name is the optional feature name (e.g., "dev", "test").
	Name string `json:"name"`
	// Dependencies are the package names required when this extra is installed.
	Dependencies []string `json:"dependencies"`
}

// PythonUvLockEntry represents a single package entry within a uv.lock file.
type PythonUvLockEntry struct {
	// Index is the package repository name where the package should be fetched from.
	Index string `mapstructure:"index" json:"index"`
	// Dependencies are the package's runtime dependencies with version constraints.
	Dependencies []PythonUvLockDependencyEntry `json:"dependencies"`
	// Extras are optional feature groups that include additional dependencies.
	Extras []PythonUvLockExtraEntry `json:"extras,omitempty"`
}
