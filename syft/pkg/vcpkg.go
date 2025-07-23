package pkg

type VcpkgRegistryKind string

const (
	FileSystem VcpkgRegistryKind = "filesystem"
	Git        VcpkgRegistryKind = "git"
	Builtin    VcpkgRegistryKind = "builtin"
)

// used for metadata. Includes summary of data found in manifest (vcpkg.json file) relevant to just that vcpkg
type VcpkgManifest struct {
	Description []string             `json:"description,omitempty"`
	Documentation   string                  `json:"documentation,omitempty"`
	// true version used. computed by info in manifest + top-level
	FullVersion string `json:"full-version"`
	License string `json:"license,omitempty"` 
	Maintainers []string        `json:"maintainers,omitempty"`
	Name        string          `json:"name"`
	Supports    string          `json:"supports,omitempty"`
	// to show where it came from
	Registry *VcpkgRegistryEntry `json:"registry,omitempty"`
	// found by looking at build folder to find target. ex. "x64-linux"
	Triplet string `json:"triplet,omitempty"`
}

// Matches definition of Vcpkg "Registry". https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-configuration-json#registry
type VcpkgRegistryEntry struct {
	Baseline   string            `json:"baseline,omitempty"`
	Kind       VcpkgRegistryKind `json:"kind"`
	Packages   []string            `json:"packages,omitempty"`
	Path       string            `json:"path,omitempty"`
	Reference  string            `json:"reference,omitempty"`
	Repository string            `json:"repository,omitempty"`
}

