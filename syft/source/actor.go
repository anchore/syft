package source

// Actor represents a person, organization, or tool that participated in the creation of the SBOM.
type Actor struct {
	Type  string `json:"type" yaml:"type" mapstructure:"type"`
	Name  string `json:"name" yaml:"name" mapstructure:"name"`
	Email string `json:"email,omitempty" yaml:"email,omitempty" mapstructure:"email,omitempty"`
}
