package pkgtestobservation

import "time"

// Observations represents capability observations during testing
type Observations struct {
	License       bool         `json:"license"`
	Relationships Relationship `json:"relationships"`
	FileListing   Count        `json:"file_listing"`
	FileDigests   Count        `json:"file_digests"`
	IntegrityHash Count        `json:"integrity_hash"`
}

// Relationship tracks dependency relationship observations
type Relationship struct {
	Found bool `json:"found"`
	Count int  `json:"count"`
}

// Count tracks whether a capability was found and how many times
type Count struct {
	Found bool `json:"found"`
	Count int  `json:"count"`
}

// Test is the root structure for test-observations.json
type Test struct {
	Package    string                `json:"package"`
	UpdatedAt  time.Time             `json:"updated_at"`
	Catalogers map[string]*Cataloger `json:"catalogers"`
	Parsers    map[string]*Parser    `json:"parsers"`
}

// Parser captures all observations for a parser
type Parser struct {
	MetadataTypes []string     `json:"metadata_types"`
	PackageTypes  []string     `json:"package_types"`
	Observations  Observations `json:"observations"`
}

// Cataloger captures all observations for a cataloger
type Cataloger struct {
	MetadataTypes []string     `json:"metadata_types"`
	PackageTypes  []string     `json:"package_types"`
	Observations  Observations `json:"observations"`
}
