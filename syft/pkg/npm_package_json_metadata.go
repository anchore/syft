package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*NpmPackageJSONMetadata)(nil)

// NpmPackageJSONMetadata holds extra information that is used in pkg.Package
type NpmPackageJSONMetadata struct {
	Name        string   `mapstructure:"name" json:"name"`
	Version     string   `mapstructure:"version" json:"version"`
	Files       []string `mapstructure:"files" json:"files,omitempty"`
	Author      string   `mapstructure:"author" json:"author"`
	Licenses    []string `mapstructure:"licenses" json:"licenses"`
	Homepage    string   `mapstructure:"homepage" json:"homepage"`
	Description string   `mapstructure:"description" json:"description"`
	URL         string   `mapstructure:"url" json:"url"`
}

// PackageURL returns the PURL for the specific NPM package (see https://github.com/package-url/purl-spec)
func (p NpmPackageJSONMetadata) PackageURL(_ *linux.Release) string {
	var namespace string
	name := p.Name

	fields := strings.SplitN(p.Name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		p.Version,
		nil,
		"",
	).ToString()
}
