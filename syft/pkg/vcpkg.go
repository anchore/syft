package pkg

type VcpkgRegistryKind string

const (
	FileSystem VcpkgRegistryKind = "filesystem"
	Git        VcpkgRegistryKind = "git"
	Builtin    VcpkgRegistryKind = "builtin"
)

// used for metadata. Includes summary of data found in manifest (vcpkg.json file) relevant to just that vcpkg
type VcpkgManifest struct {
	// Description describes what the package does; required for library ports
	Description []string `json:"description,omitempty"`
	// Documentation is the URL to the upstream project's documentation
	Documentation string `json:"documentation,omitempty"`
	// FullVersion is the complete version string combining version and port-version (e.g., "11.0.2#1")
	FullVersion string `json:"full-version"`
	// Version is the upstream project version using one of vcpkg's versioning schemes (version, version-semver, version-date, or version-string)
	Version string `json:"version"`
	// PortVersion is the revision number for packaging changes when upstream version is unchanged
	PortVersion int `json:"port-version"`
	// License is the SPDX license expression for the package
	License string `json:"license,omitempty"`
	// Maintainers is the contact information for package maintainers
	Maintainers []string `json:"maintainers,omitempty"`
	// Name is the package identifier; must be lowercase alphanumeric with hyphens
	Name string `json:"name"`
	// Supports is the platform expression documenting supported build configurations
	Supports string `json:"supports,omitempty"`
	// Registry shows where the package came from
	Registry *VcpkgRegistryEntry `json:"registry,omitempty"`
	// Triplet is the target build configuration defining architecture, platform, and library linkage (e.g., "x64-linux", "arm64-windows-static"). Detected from CMakeCache.txt's VCPKG_TARGET_TRIPLET or vcpkg installation path.
	Triplet string `json:"triplet,omitempty"`
}

// Matches definition of Vcpkg "Registry". https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-configuration-json#registry
type VcpkgRegistryEntry struct {
	Baseline   string            `json:"baseline,omitempty"`
	Kind       VcpkgRegistryKind `json:"kind"`
	Packages   []string          `json:"packages,omitempty"`
	Path       string            `json:"path,omitempty"`
	Reference  string            `json:"reference,omitempty"`
	Repository string            `json:"repository,omitempty"`
}
