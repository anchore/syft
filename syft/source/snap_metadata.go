package source

type SnapMetadata struct {
	Summary       string   `yaml:"summary" json:"summary,omitempty"`
	Base          string   `yaml:"base" json:"base,omitempty"`
	Grade         string   `yaml:"grade" json:"grade,omitempty"`
	Confinement   string   `yaml:"confinement" json:"confinement,omitempty"`
	Architectures []string `yaml:"architectures" json:"architectures,omitempty"`
}
