package pkg

type VcpkgRegistryKind string

const (
	FileSystem VcpkgRegistryKind = "filesystem"
	Git        VcpkgRegistryKind = "git"
	Builtin    VcpkgRegistryKind = "builtin"
)

// VcpkgManifest summarizes the data found in a vcpkg manifest (vcpkg.json) relevant to a single vcpkg package.
type VcpkgManifest struct {
	// Description is the human-readable description of the package (may be a single string or a list of paragraphs in the manifest).
	Description []string `json:"description,omitempty"`

	// Documentation is the URL to the package's documentation.
	Documentation string `json:"documentation,omitempty"`

	// FullVersion is the complete version string including the port-version suffix (e.g. "1.2.3#2").
	FullVersion string `json:"full-version"`

	// Version is the upstream package version without the port-version suffix (e.g. "1.2.3").
	Version string `json:"version"`

	// PortVersion is the vcpkg-specific packaging revision for a given upstream version.
	PortVersion int `json:"port-version"`

	// Maintainers are the people responsible for maintaining the vcpkg port.
	Maintainers []string `json:"maintainers,omitempty"`

	// Name is the package name as declared in the manifest.
	Name string `json:"name"`

	// Supports is the platform expression describing which triplets the package can be built for (e.g. "!windows").
	Supports string `json:"supports,omitempty"`

	// Registry indicates where the package definition came from.
	Registry *VcpkgRegistryEntry `json:"registry,omitempty"`

	// Triplet is the build target discovered from the build folder (e.g. "x64-linux").
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
