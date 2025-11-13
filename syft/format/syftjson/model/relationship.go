package model

// Relationship represents a directed relationship between two artifacts in the SBOM, such as package-contains-file or package-depends-on-package.
type Relationship struct {
	// Parent is the ID of the parent artifact in this relationship.
	Parent string `json:"parent"`

	// Child is the ID of the child artifact in this relationship.
	Child string `json:"child"`

	// Type is the relationship type (e.g., "contains", "dependency-of", "ancestor-of").
	Type string `json:"type"`

	// Metadata contains additional relationship-specific metadata.
	Metadata interface{} `json:"metadata,omitempty"`
}
