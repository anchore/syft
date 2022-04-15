package github

// Derived from: https://gist.github.com/reiddraper/fdab2883db0f372c146d1a750fc1c43f

type DependencySnapshot struct {
	Version   int              `json:"version"`
	Job       Job              `json:"job,omitempty"` // !omitempty
	Sha       string           `json:"sha,omitempty"` // !omitempty sha of the Git commit
	Ref       string           `json:"ref,omitempty"` // !omitempty ref of the Git commit example "refs/heads/main"
	Detector  DetectorMetadata `json:"detector,omitempty"`
	Metadata  Metadata         `json:"metadata,omitempty"`
	Manifests Manifests        `json:"manifests,omitempty"`
	Scanned   ISO8601Date      `json:"scanned,omitempty"`
}

type Job struct {
	Correlator string `json:"correlator,omitempty"` // !omitempty
	ID         string `json:"id,omitempty"`         // !omitempty
	HTMLURL    string `json:"html_url,omitempty"`
}

type DetectorMetadata struct {
	Name    string `json:"name,omitempty"`
	URL     string `json:"url,omitempty"`
	Version string `json:"version,omitempty"`
}

type Manifests map[string]Manifest

// Manifest A collection of related dependencies, either declared in a file,
// or representing a logical group of dependencies.
type Manifest struct {
	Name     string          `json:"name"`
	File     FileInfo        `json:"file"`
	Metadata Metadata        `json:"metadata,omitempty"`
	Resolved DependencyGraph `json:"resolved,omitempty"`
}

type FileInfo struct {
	SourceLocation string `json:"source_location,omitempty"`
}

// DependencyRelationship A notation of whether a dependency is requested directly
// by this manifest, or is a dependency of another dependency.
type DependencyRelationship string

const (
	DependencyRelationshipDirect   DependencyRelationship = "direct"
	DependencyRelationshipIndirect DependencyRelationship = "indirect"
)

// DependencyScope A notation of whether the dependency is required for the primary
// build artifact (runtime), or is only used for development.
// Future versions of this specification may allow for more granular
// scopes, like `runtimeserver`, `runtimeshipped`,
// `developmenttest`, `developmentbenchmark`.
type DependencyScope string

const (
	DependencyScopeRuntime     DependencyScope = "runtime"
	DependencyScopeDevelopment DependencyScope = "development"
)

type DependencyNode struct {
	PackageURL   string                 `json:"package_url,omitempty"`
	Metadata     Metadata               `json:"metadata,omitempty"`
	Relationship DependencyRelationship `json:"relationship,omitempty"`
	Scope        DependencyScope        `json:"scope,omitempty"`
	Dependencies []string               `json:"dependencies,omitempty"`
}

type DependencyGraph map[string]DependencyNode

type ISO8601Date = string

type Scalar interface{} // should be: null | boolean | string | number

type Metadata map[string]Scalar
