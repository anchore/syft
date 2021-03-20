package config

type Packages struct {
	Cataloger catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
}

func (cfg *Packages) build() error {
	return cfg.Cataloger.build()
}
