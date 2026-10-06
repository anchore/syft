package exp

// ArtifactDetectionMethod identifies an artifact detection method.
type ArtifactDetectionMethod string

const (
	GlobDetection     ArtifactDetectionMethod = "glob"
	PathDetection     ArtifactDetectionMethod = "path"
	MIMETypeDetection ArtifactDetectionMethod = "mimetype"
)

// Capabilities describes one package cataloger.
type Capabilities struct {
	Ecosystem       string        `json:"ecosystem"`
	Name            string        `json:"name"`
	Type            string        `json:"type"`
	Source          Source        `json:"source"`
	Config          string        `json:"config,omitempty"`
	Selectors       []string      `json:"selectors,omitempty"`
	Parsers         []Parser      `json:"parsers,omitempty"`
	Detectors       []Detector    `json:"detectors,omitempty"`
	MetadataTypes   []string      `json:"metadata_types,omitempty"`
	PackageTypes    []string      `json:"package_types,omitempty"`
	PURLTypes       []string      `json:"purl_types,omitempty"`
	JSONSchemaTypes []string      `json:"json_schema_types,omitempty"`
	Capabilities    CapabilitySet `json:"capabilities,omitempty"`
}

// Source identifies the source code that defines a cataloger.
type Source struct {
	File     string `json:"file"`
	Function string `json:"function"`
}

// Parser describes a parser and its artifact detector.
type Parser struct {
	ParserFunction  string        `json:"function"`
	Detector        Detector      `json:"detector"`
	MetadataTypes   []string      `json:"metadata_types,omitempty"`
	PackageTypes    []string      `json:"package_types,omitempty"`
	PURLTypes       []string      `json:"purl_types,omitempty"`
	JSONSchemaTypes []string      `json:"json_schema_types,omitempty"`
	Capabilities    CapabilitySet `json:"capabilities,omitempty"`
}

// Detector describes how Syft finds an artifact.
type Detector struct {
	Method     ArtifactDetectionMethod `json:"method"`
	Criteria   []string                `json:"criteria"`
	Conditions []DetectorCondition     `json:"conditions,omitempty"`
	Packages   []DetectorPackageInfo   `json:"packages,omitempty"`
	Comment    string                  `json:"comment,omitempty"`
}

// DetectorCondition describes when a detector is active.
type DetectorCondition struct {
	When    map[string]any `json:"when"`
	Comment string         `json:"comment,omitempty"`
}

// DetectorPackageInfo describes a package that a detector can create.
type DetectorPackageInfo struct {
	Class string   `json:"class"`
	Name  string   `json:"name"`
	PURL  string   `json:"purl"`
	CPEs  []string `json:"cpes"`
	Type  string   `json:"type"`
}

// CapabilitySet contains cataloger capability fields.
type CapabilitySet []CapabilityField

// CapabilityField describes one cataloger capability.
type CapabilityField struct {
	Name       string                `json:"name"`
	Default    any                   `json:"default"`
	Conditions []CapabilityCondition `json:"conditions,omitempty"`
	Evidence   []string              `json:"evidence,omitempty"`
	Comment    string                `json:"comment,omitempty"`
}

// CapabilityCondition describes a conditional capability value.
type CapabilityCondition struct {
	When    map[string]any `json:"when"`
	Value   any            `json:"value"`
	Comment string         `json:"comment,omitempty"`
}
