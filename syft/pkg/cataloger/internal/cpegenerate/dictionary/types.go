package dictionary

import (
	"encoding/json"
	"slices"

	"github.com/scylladb/go-set/strset"
)

const (
	EcosystemNPM              = "npm"
	EcosystemRubyGems         = "rubygems"
	EcosystemPyPI             = "pypi"
	EcosystemPHPPear          = "php_pear"
	EcosystemPHPPecl          = "php_pecl"
	EcosystemPHPComposer      = "php_composer"
	EcosystemJenkinsPlugins   = "jenkins_plugins"
	EcosystemRustCrates       = "rust_crates"
	EcosystemGoModules        = "go_modules"
	EcosystemWordpressPlugins = "wordpress_plugins"
	EcosystemWordpressThemes  = "wordpress_themes"
)

type Indexed struct {
	EcosystemPackages map[string]Packages `json:"ecosystems"`
}

type Set struct {
	*strset.Set
}

type Packages map[string]*Set

func NewSet(ts ...string) *Set {
	return &Set{strset.New(ts...)}
}

func (s *Set) MarshalJSON() ([]byte, error) {
	l := s.List()
	slices.Sort(l)
	return json.Marshal(l)
}

func (s *Set) UnmarshalJSON(data []byte) error {
	var strSlice []string

	if err := json.Unmarshal(data, &strSlice); err == nil {
		*s = *NewSet(strSlice...)
	} else {
		return err
	}
	return nil
}
