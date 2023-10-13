package options

// Config holds a reference to the specific config file that was used to load application configuration
type Config struct {
	ConfigFile string `yaml:"config" json:"config" mapstructure:"config"`
}
