package config

type development struct {
	ProfileCPU bool `yaml:"profile-cpu" json:"profile-cpu" mapstructure:"profile-cpu"`
	ProfileMem bool `yaml:"profile-mem" json:"profile-mem" mapstructure:"profile-mem"`
}
