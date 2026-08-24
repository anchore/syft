package exp

// ArtifactDetectionMethod specifies the type of artifact detection mechanism.
type ArtifactDetectionMethod string

const (
	GlobDetection     ArtifactDetectionMethod = "glob"
	PathDetection     ArtifactDetectionMethod = "path"
	MIMETypeDetection ArtifactDetectionMethod = "mimetype"
)

// Document represents the root structure of the capabilities data.
type Document struct {
	Configs           map[string]CatalogerConfigEntry `yaml:"configs,omitempty" json:"configs,omitempty"`
	ApplicationConfig []ApplicationConfigField        `yaml:"application,omitempty" json:"application,omitempty"`
	Catalogers        []Capabilities                  `yaml:"catalogers" json:"catalogers"`
}

type CatalogerConfigFieldEntry struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	AppKey      string `yaml:"app_key,omitempty" json:"app_key,omitempty"`
}

type CatalogerConfigEntry struct {
	Fields []CatalogerConfigFieldEntry `yaml:"fields" json:"fields"`
}

type ApplicationConfigField struct {
	Key          string `yaml:"key" json:"key"`
	Description  string `yaml:"description" json:"description"`
	DefaultValue any    `yaml:"default,omitempty" json:"default,omitempty"`
}

type Source struct {
	File     string `yaml:"file" json:"file"`
	Function string `yaml:"function" json:"function"`
}

type Detector struct {
	Method     ArtifactDetectionMethod `yaml:"method" json:"method"`
	Criteria   []string                `yaml:"criteria" json:"criteria"`
	Conditions []DetectorCondition     `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Packages   []DetectorPackageInfo   `yaml:"packages,omitempty" json:"packages,omitempty"`
	Comment    string                  `yaml:"comment,omitempty" json:"comment,omitempty"`
}

type DetectorPackageInfo struct {
	Class string   `yaml:"class" json:"class"`
	Name  string   `yaml:"name" json:"name"`
	PURL  string   `yaml:"purl" json:"purl"`
	CPEs  []string `yaml:"cpes" json:"cpes"`
	Type  string   `yaml:"type" json:"type"`
}

type DetectorCondition struct {
	When    map[string]any `yaml:"when" json:"when"`
	Comment string         `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Capabilities describes one package cataloger's capability metadata.
type Capabilities struct {
	Ecosystem       string        `yaml:"ecosystem" json:"ecosystem"`
	Name            string        `yaml:"name" json:"name"`
	Type            string        `yaml:"type" json:"type"`
	Source          Source        `yaml:"source" json:"source"`
	Config          string        `yaml:"config,omitempty" json:"config,omitempty"`
	Selectors       []string      `yaml:"selectors,omitempty" json:"selectors,omitempty"`
	Parsers         []Parser      `yaml:"parsers,omitempty" json:"parsers,omitempty"`
	Detectors       []Detector    `yaml:"detectors,omitempty" json:"detectors,omitempty"`
	MetadataTypes   []string      `yaml:"metadata_types,omitempty" json:"metadata_types,omitempty"`
	PackageTypes    []string      `yaml:"package_types,omitempty" json:"package_types,omitempty"`
	PURLTypes       []string      `yaml:"purl_types,omitempty" json:"purl_types,omitempty"`
	JSONSchemaTypes []string      `yaml:"json_schema_types,omitempty" json:"json_schema_types,omitempty"`
	Capabilities    CapabilitySet `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type Parser struct {
	ParserFunction  string        `yaml:"function" json:"function"`
	Detector        Detector      `yaml:"detector" json:"detector"`
	MetadataTypes   []string      `yaml:"metadata_types,omitempty" json:"metadata_types,omitempty"`
	PackageTypes    []string      `yaml:"package_types,omitempty" json:"package_types,omitempty"`
	PURLTypes       []string      `yaml:"purl_types,omitempty" json:"purl_types,omitempty"`
	JSONSchemaTypes []string      `yaml:"json_schema_types,omitempty" json:"json_schema_types,omitempty"`
	Capabilities    CapabilitySet `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

type CapabilityField struct {
	Name       string                `yaml:"name" json:"name"`
	Default    any                   `yaml:"default" json:"default"`
	Conditions []CapabilityCondition `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Evidence   []string              `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	Comment    string                `yaml:"comment,omitempty" json:"comment,omitempty"`
}

type CapabilityCondition struct {
	When    map[string]any `yaml:"when" json:"when"`
	Value   any            `yaml:"value" json:"value"`
	Comment string         `yaml:"comment,omitempty" json:"comment,omitempty"`
}

type CapabilitySet []CapabilityField
