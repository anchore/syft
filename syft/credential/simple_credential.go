package credential

type SimpleCredential struct {
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (pc SimpleCredential) Valid() bool {
	return pc.Username != "" && pc.Password != ""
}
