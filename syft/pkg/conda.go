package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// CondaPathData represents metadata for a single file within a Conda package from the paths.json file.
type CondaPathData struct {
	// Path is the file path relative to the Conda environment root.
	Path string `json:"_path"`

	// PathType indicates the link type for the file (e.g., "hardlink", "softlink", "directory").
	PathType string `json:"path_type"`

	// SHA256 is the SHA-256 hash of the file contents.
	SHA256 string `json:"sha256"`

	// SHA256InPrefix is the SHA-256 hash of the file after prefix replacement during installation.
	SHA256InPrefix string `json:"sha256_in_prefix"`

	// SizeInBytes is the file size in bytes.
	SizeInBytes int64 `json:"size_in_bytes"`
}

// CondaPathsData represents the paths.json file structure from a Conda package containing file metadata.
type CondaPathsData struct {
	// PathsVersion is the schema version of the paths data format.
	PathsVersion int `json:"paths_version"`

	// Paths is the list of file metadata entries for all files in the package.
	Paths []CondaPathData `json:"paths"`
}

// CondaLink represents link metadata from a Conda package's link.json file describing package installation source.
type CondaLink struct {
	// Source is the original path where the package was extracted from cache.
	Source string `json:"source"`

	// Type indicates the link type (1 for hard link, 2 for soft link, 3 for copy).
	Type int `json:"type"`
}

// CondaMetaPackage represents metadata for a Conda package extracted from the conda-meta/*.json files.
type CondaMetaPackage struct {
	// Arch is the target CPU architecture for the package (e.g., "arm64", "x86_64").
	Arch string `json:"arch,omitempty"`

	// Name is the package name as found in the conda-meta JSON file.
	Name string `json:"name"`

	// Version is the package version as found in the conda-meta JSON file.
	Version string `json:"version"`

	// Build is the build string identifier (e.g., "h90dfc92_1014").
	Build string `json:"build"`

	// BuildNumber is the sequential build number for this version.
	BuildNumber int `json:"build_number"`

	// Channel is the Conda channel URL where the package was retrieved from.
	Channel string `json:"channel,omitempty"`

	// Subdir is the subdirectory within the channel (e.g., "osx-arm64", "linux-64").
	Subdir string `json:"subdir,omitempty"`

	// Noarch indicates if the package is platform-independent (e.g., "python", "generic").
	Noarch string `json:"noarch,omitempty"`

	// License is the package license identifier.
	License string `json:"license,omitempty"`

	// LicenseFamily is the general license category (e.g., "MIT", "Apache", "GPL").
	LicenseFamily string `json:"license_family,omitempty"`

	// MD5 is the MD5 hash of the package archive.
	MD5 string `json:"md5,omitempty"`

	// SHA256 is the SHA-256 hash of the package archive.
	SHA256 string `json:"sha256,omitempty"`

	// Size is the package archive size in bytes.
	Size int64 `json:"size,omitempty"`

	// Timestamp is the Unix timestamp when the package was built.
	Timestamp int64 `json:"timestamp,omitempty"`

	// Filename is the original package archive filename (e.g., "zlib-1.2.11-h90dfc92_1014.tar.bz2").
	Filename string `json:"fn,omitempty"`

	// URL is the full download URL for the package archive.
	URL string `json:"url,omitempty"`

	// ExtractedPackageDir is the local cache directory where the package was extracted.
	ExtractedPackageDir string `json:"extracted_package_dir,omitempty"`

	// Depends is the list of runtime dependencies with version constraints.
	Depends []string `json:"depends,omitempty"`

	// Files is the list of files installed by this package.
	Files []string `json:"files,omitempty"`

	// PathsData contains detailed file metadata from the paths.json file.
	PathsData *CondaPathsData `json:"paths_data,omitempty"`

	// Link contains installation source metadata from the link.json file.
	Link *CondaLink `json:"link,omitempty"`
}

func (m CondaMetaPackage) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f != "" {
			s.Add(f)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
