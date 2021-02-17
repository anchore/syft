package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ fileOwner = (*NpmPackageJSONMetadata)(nil)

// NpmPackageJSONMetadata holds extra information that is used in pkg.Package
type NpmPackageJSONMetadata struct {
	Files       []string `mapstructure:"files" json:"files,omitempty"`
	Author      string   `mapstructure:"author" json:"author"`
	Licenses    []string `mapstructure:"licenses" json:"licenses"`
	Homepage    string   `mapstructure:"homepage" json:"homepage"`
	Description string   `mapstructure:"description" json:"description"`
	URL         string   `mapstructure:"url" json:"url"`
}

func (m NpmPackageJSONMetadata) ownedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f != "" {
			s.Add(f)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
