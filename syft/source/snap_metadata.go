package source

type SnapMetadata struct {
	Summary       string   `yaml:"summary" json:"summary"`
	Base          string   `yaml:"base" json:"base"`
	Grade         string   `yaml:"grade" json:"grade"`
	Confinement   string   `yaml:"confinement" json:"confinement"`
	Architectures []string `yaml:"architectures" json:"architectures"`
}
