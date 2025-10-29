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

// Document represents the root structure of the capabilities YAML file
type Document struct {
	Configs           map[string]CatalogerConfigEntry `yaml:"configs,omitempty" json:"configs,omitempty"`         // config structs with their fields
	ApplicationConfig []ApplicationConfigField        `yaml:"application,omitempty" json:"application,omitempty"` // application-level config keys
	Catalogers        []CatalogerEntry                `yaml:"catalogers" json:"catalogers"`
}

// CatalogerConfigFieldEntry represents a single field in a cataloger configuration struct
type CatalogerConfigFieldEntry struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	AppKey      string `yaml:"app_key,omitempty" json:"app_key,omitempty"` // maps to app-level config key
}

// CatalogerConfigEntry represents a complete configuration struct (e.g., golang.CatalogerConfig)
type CatalogerConfigEntry struct {
	Fields []CatalogerConfigFieldEntry `yaml:"fields" json:"fields"`
}

// ApplicationConfigField represents an application-level configuration field
type ApplicationConfigField struct {
	Key          string `yaml:"key" json:"key"`
	Description  string `yaml:"description" json:"description"`
	DefaultValue any    `yaml:"default,omitempty" json:"default,omitempty"`
}

// Source describes the source code location of a cataloger
type Source struct {
	File     string `yaml:"file" json:"file"`         // AUTO-GENERATED for generic, MANUAL for custom
	Function string `yaml:"function" json:"function"` // AUTO-GENERATED for generic, MANUAL for custom
}

// Detector describes how artifacts are detected (method and criteria)
type Detector struct {
	Method     ArtifactDetectionMethod `yaml:"method" json:"method"`                             // AUTO-GENERATED
	Criteria   []string                `yaml:"criteria" json:"criteria"`                         // AUTO-GENERATED
	Conditions []DetectorCondition     `yaml:"conditions,omitempty" json:"conditions,omitempty"` // MANUAL - when this detector should be active
	Packages   []DetectorPackageInfo   `yaml:"packages,omitempty" json:"packages,omitempty"`     // AUTO-GENERATED for binary-classifier-cataloger
	Comment    string                  `yaml:"comment,omitempty" json:"comment,omitempty"`       // MANUAL - explanation of this detector
}

// DetectorPackageInfo describes package information that a detector can produce
type DetectorPackageInfo struct {
	Class string   `yaml:"class" json:"class"` // classifier class (e.g., "python-binary-lib")
	Name  string   `yaml:"name" json:"name"`   // package name (e.g., "python")
	PURL  string   `yaml:"purl" json:"purl"`   // package URL without version (e.g., "pkg:generic/python")
	CPEs  []string `yaml:"cpes" json:"cpes"`   // CPE strings
	Type  string   `yaml:"type" json:"type"`   // package type (e.g., "BinaryPkg")
}

// DetectorCondition specifies when a detector should be active based on configuration
type DetectorCondition struct {
	// When specifies config field names and their required values (all must match - AND logic)
	When map[string]any `yaml:"when" json:"when"`
	// Comment provides optional explanation of this condition
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// CatalogerEntry represents a single cataloger's capabilities
type CatalogerEntry struct {
	Ecosystem       string        `yaml:"ecosystem" json:"ecosystem"`                                     // MANUAL - ecosystem categorization (e.g., "python", "java", "javascript")
	Name            string        `yaml:"name" json:"name"`                                               // AUTO-GENERATED for generic, MANUAL for custom
	Type            string        `yaml:"type" json:"type"`                                               // AUTO-GENERATED: "generic" or "custom"
	Source          Source        `yaml:"source" json:"source"`                                           // AUTO-GENERATED for generic, MANUAL for custom
	Config          string        `yaml:"config,omitempty" json:"config,omitempty"`                       // e.g., "golang.CatalogerConfig"
	Selectors       []string      `yaml:"selectors,omitempty" json:"selectors,omitempty"`                 // AUTO-GENERATED - cataloger name tags for selection
	Parsers         []Parser      `yaml:"parsers,omitempty" json:"parsers,omitempty"`                     // AUTO-GENERATED structure, only for type=generic
	Detectors       []Detector    `yaml:"detectors,omitempty" json:"detectors,omitempty"`                 // AUTO-GENERATED - detection methods (only for type=custom)
	MetadataTypes   []string      `yaml:"metadata_types,omitempty" json:"metadata_types,omitempty"`       // AUTO-GENERATED - pkg metadata types emitted (only for type=custom)
	PackageTypes    []string      `yaml:"package_types,omitempty" json:"package_types,omitempty"`         // AUTO-GENERATED - package types emitted (only for type=custom)
	JSONSchemaTypes []string      `yaml:"json_schema_types,omitempty" json:"json_schema_types,omitempty"` // AUTO-GENERATED - JSON schema type names (UpperCamelCase)
	Capabilities    CapabilitySet `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`           // MANUAL - config-driven capability definitions (only for type=custom)
}

// Parser represents a parser function and its artifact detection criteria for generic catalogers
type Parser struct {
	ParserFunction  string        `yaml:"function" json:"function"`                                       // AUTO-GENERATED (used as preservation key)
	Detector        Detector      `yaml:"detector" json:"detector"`                                       // AUTO-GENERATED - how artifacts are detected
	MetadataTypes   []string      `yaml:"metadata_types,omitempty" json:"metadata_types,omitempty"`       // AUTO-GENERATED - pkg metadata types emitted by this parser
	PackageTypes    []string      `yaml:"package_types,omitempty" json:"package_types,omitempty"`         // AUTO-GENERATED - package types emitted by this parser
	JSONSchemaTypes []string      `yaml:"json_schema_types,omitempty" json:"json_schema_types,omitempty"` // AUTO-GENERATED - JSON schema type names (UpperCamelCase)
	Capabilities    CapabilitySet `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`           // MANUAL - config-driven capability definitions
}

// CapabilityField represents a single capability field with optional conditional values based on configuration.
// This is the V2 capabilities format that replaces the mode-based approach.
type CapabilityField struct {
	// Name is the dot-notation path to the capability (e.g., "license", "dependency.depth")
	Name string `yaml:"name" json:"name"`
	// Default is the value when no conditions match
	Default any `yaml:"default" json:"default"`
	// Conditions are optional conditional overrides evaluated in order (first match wins)
	Conditions []CapabilityCondition `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	// Evidence provides optional references to source code that implements this capability
	Evidence []string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	// Comment provides optional human-readable explanation
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// CapabilityCondition represents a conditional override for a capability field value.
// When the config fields specified in When match, the Value is used instead of Default.
type CapabilityCondition struct {
	// When specifies config field names and their required values (all must match - AND logic)
	// Example: {"SearchRemoteLicenses": true, "UseNetwork": true}
	When map[string]any `yaml:"when" json:"when"`
	// Value is the capability value when the condition matches
	Value any `yaml:"value" json:"value"`
	// Comment provides optional explanation of this condition
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// CapabilitySet represents a collection of capability fields (V2 format)
type CapabilitySet []CapabilityField
