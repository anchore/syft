package options

import "github.com/anchore/fangs"

// Config holds a reference to the specific config file that was used to load application configuration
type Config struct {
	ConfigFile string `yaml:"config" json:"config" mapstructure:"config"`
}

func (cfg *Config) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&cfg.ConfigFile, "the configuration file that was used to load application configuration")
}
