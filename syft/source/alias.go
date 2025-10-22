package source

type Alias struct {
	Name     string `json:"name" yaml:"name" mapstructure:"name"`
	Version  string `json:"version" yaml:"version" mapstructure:"version"`
	Supplier string `json:"supplier" yaml:"supplier" mapstructure:"supplier"`
}

func (a *Alias) IsEmpty() bool {
	if a == nil {
		return true
	}
	return a.Name == "" && a.Version == ""
}
