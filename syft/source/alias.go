package source

import "github.com/anchore/syft/syft/sort"

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

func (a Alias) Compare(other Alias) int {
	if i := sort.CompareOrd(a.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(a.Version, other.Version); i != 0 {
		return i
	}

	return 0
}
