package capabilities

// ArtifactDetectionMethod specifies the type of artifact detection mechanism
type ArtifactDetectionMethod string

const (
	// GlobDetection matches artifacts using glob patterns (e.g., "**/*.jar", "*.pyc")
	GlobDetection ArtifactDetectionMethod = "glob"
	// PathDetection matches artifacts by exact file path (e.g., "/usr/bin/python", "package.json")
	PathDetection ArtifactDetectionMethod = "path"
	// MIMETypeDetection matches artifacts by MIME type (e.g., "application/x-executable", "text/x-python")
	MIMETypeDetection ArtifactDetectionMethod = "mimetype"
)

// EnrichmentMode describes how a cataloger performs its discovery work
type EnrichmentMode string

func (e EnrichmentMode) String() string {
	return string(e)
}

const (
	// OfflineMode indicates cataloging using only information available in the artifact itself
	OfflineMode EnrichmentMode = "offline"
	// OnlineMode indicates cataloging that may fetch additional metadata from external sources
	OnlineMode EnrichmentMode = "online"
	// ToolExecutionMode indicates cataloging that requires executing tools or binaries in the artifact
	ToolExecutionMode EnrichmentMode = "tool-execution"
)

// Document represents the root structure of the capabilities YAML file
type Document struct {
	Catalogers []CatalogerEntry `yaml:"catalogers"`
}

// Source describes the source code location of a cataloger
type Source struct {
	File     string `yaml:"file"`     // AUTO-GENERATED for generic, MANUAL for custom
	Function string `yaml:"function"` // AUTO-GENERATED for generic, MANUAL for custom
}

// ConfigField represents optional configuration for a detector
type ConfigField struct {
	Key   string      `yaml:"key"`
	Value interface{} `yaml:"value,omitempty"`
}

// Detector describes how artifacts are detected (method and criteria)
type Detector struct {
	Method   ArtifactDetectionMethod `yaml:"method"`           // AUTO-GENERATED
	Criteria []string                `yaml:"criteria"`         // AUTO-GENERATED
	Config   *ConfigField            `yaml:"config,omitempty"` // convey if detector is used or configured
}

// CatalogerEntry represents a single cataloger's capabilities
type CatalogerEntry struct {
	Ecosystem     string                         `yaml:"ecosystem"`                // MANUAL - ecosystem categorization (e.g., "python", "java", "javascript")
	Name          string                         `yaml:"name"`                     // AUTO-GENERATED for generic, MANUAL for custom
	Type          string                         `yaml:"type"`                     // AUTO-GENERATED: "generic" or "custom"
	Source        Source                         `yaml:"source"`                   // AUTO-GENERATED for generic, MANUAL for custom
	Selectors     []string                       `yaml:"selectors,omitempty"`      // AUTO-GENERATED - cataloger name tags for selection
	Parsers       []Parser                       `yaml:"parsers,omitempty"`        // AUTO-GENERATED structure, only for type=generic
	Detectors     []Detector                     `yaml:"detectors,omitempty"`      // AUTO-GENERATED - detection methods (only for type=custom)
	MetadataTypes []string                       `yaml:"metadata_types,omitempty"` // AUTO-GENERATED - pkg metadata types emitted (only for type=custom)
	PackageTypes  []string                       `yaml:"package_types,omitempty"`  // AUTO-GENERATED - package types emitted (only for type=custom)
	Capabilities  map[EnrichmentMode]*Capability `yaml:"capabilities,omitempty"`   // MANUAL, only for type=custom (cataloger-level capabilities)
}

// Parser represents a parser function and its artifact detection criteria for generic catalogers
type Parser struct {
	ParserFunction string                         `yaml:"function"`                 // AUTO-GENERATED (used as preservation key)
	Detector       Detector                       `yaml:"detector"`                 // AUTO-GENERATED - how artifacts are detected
	MetadataTypes  []string                       `yaml:"metadata_types,omitempty"` // AUTO-GENERATED - pkg metadata types emitted by this parser
	PackageTypes   []string                       `yaml:"package_types,omitempty"`  // AUTO-GENERATED - package types emitted by this parser
	Capabilities   map[EnrichmentMode]*Capability `yaml:"capabilities"`             // MANUAL - preserved across regeneration
}

// Capability describes what information a cataloger can discover in a specific enrichment mode
type Capability struct {
	License        *bool                       `yaml:"license,omitempty"`
	Dependencies   *DependencyCapabilities     `yaml:"dependencies,omitempty"`
	PackageManager *PackageManagerCapabilities `yaml:"package_manager,omitempty"`
}

// FileCapabilities describes what file-related metadata can be discovered
type FileCapabilities struct {
	Listing *bool `yaml:"listing,omitempty"`
	Digests *bool `yaml:"digests,omitempty"`
}

// PackageManagerCapabilities describes what package manager metadata can be discovered
type PackageManagerCapabilities struct {
	Files                *FileCapabilities `yaml:"files,omitempty"`
	PackageIntegrityHash *bool             `yaml:"package_integrity_hash,omitempty"`
}

// DependencyCapabilities describes what dependency information can be discovered
type DependencyCapabilities struct {
	// Reach specifies which dependency depths can be discovered.
	// - direct: only immediate dependencies
	// - indirect: dependencies of dependencies (transitive)
	// Examples: ["direct"], ["direct", "indirect"]
	Reach []string `yaml:"reach"`
	// Topology describes the completeness of the dependency graph.
	// Possible values: "flat", "reduced" (some relationships), "complete" (full graph)
	Topology string `yaml:"topology,omitempty"`
	// Kinds specifies which dependency types can be discovered.
	// Examples: ["runtime"], ["runtime", "build", "dev"]
	Kinds []string `yaml:"kinds"`
}
