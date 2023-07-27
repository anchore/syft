package source

type Alias struct {
	Name    string `json:"name" yaml:"name" mapstructure:"name"`
	Version string `json:"version" yaml:"version" mapstructure:"version"`
}

func (a *Alias) IsEmpty() bool {
	if a == nil {
		return true
	}
	return a.Name == "" && a.Version == ""
}
