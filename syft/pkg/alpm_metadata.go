package pkg

import (
	"sort"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/scylladb/go-set/strset"
)

const AlpmDBGlob = "/var/lib/pacman/local/**/desc"

type AlpmMetadata struct {
	Package string           `mapstructure:"name" json:"package"`
	Version string           `mapstructure:"version" json:"version"`
	Epoch   *string          `mapstructure:"epoch" json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`
	Arch    string           `mapstructure:"arch" json:"architecture"`
	License string           `mapstructure:"license" json:"license"`
	Files   []AlpmFileRecord `json:"files"`
}

// TODO: Implement mtree support
type AlpmFileRecord struct {
	Path string `json:"path"`
}

// PackageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func (m AlpmMetadata) PackageURL(distro *linux.Release) string {
	return packageurl.NewPackageURL(
		"archlinux",
		"",
		"",
		"",
		packageurl.Qualifiers{},
		"",
	).ToString()
}

func (m AlpmMetadata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
