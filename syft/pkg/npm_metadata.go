package pkg

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
	for _, f := range m.Files {
		if f != "" {
			result = append(result, f)
		}
	}
	return
}
