package config

import "github.com/spf13/viper"

type anchore struct {
	// upload options
	Host string `yaml:"host" json:"host" mapstructure:"host"` // -H , hostname of the engine/enterprise instance to upload to (setting this value enables upload)
	Path string `yaml:"path" json:"path" mapstructure:"path"` // override the engine/enterprise API upload path
	// IMPORTANT: do not show the username in any YAML/JSON output (sensitive information)
	Username string `yaml:"-" json:"-" mapstructure:"username"` // -u , username to authenticate upload
	// IMPORTANT: do not show the password in any YAML/JSON output (sensitive information)
	Password               string `yaml:"-" json:"-" mapstructure:"password"`                                                               // -p , password to authenticate upload
	Dockerfile             string `yaml:"dockerfile" json:"dockerfile" mapstructure:"dockerfile"`                                           // -d , dockerfile to attach for upload
	OverwriteExistingImage bool   `yaml:"overwrite-existing-image" json:"overwrite-existing-image" mapstructure:"overwrite-existing-image"` // --overwrite-existing-image , if any of the SBOM components have already been uploaded this flag will ensure they are overwritten with the current upload
	ImportTimeout          uint   `yaml:"import-timeout" json:"import-timeout" mapstructure:"import-timeout"`                               // --import-timeout
	// , customize the number of seconds within which the SBOM import must be completed or canceled
}

func (cfg anchore) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("anchore.path", "")
}
