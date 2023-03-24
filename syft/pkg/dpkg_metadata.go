package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

const DpkgDBGlob = "**/var/lib/dpkg/{status,status.d/**}"

var _ FileOwner = (*DpkgMetadata)(nil)

// DpkgMetadata represents all captured data for a Debian package DB entry; available fields are described
// at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html in the --showformat section.
type DpkgMetadata struct {
	Package       string           `mapstructure:"Package" json:"package"`
	Source        string           `mapstructure:"Source" json:"source" cyclonedx:"source"`
	Version       string           `mapstructure:"Version" json:"version"`
	SourceVersion string           `mapstructure:"SourceVersion" json:"sourceVersion" cyclonedx:"sourceVersion"`
	Architecture  string           `mapstructure:"Architecture" json:"architecture"`
	Maintainer    string           `mapstructure:"Maintainer" json:"maintainer"`
	InstalledSize int              `mapstructure:"InstalledSize" json:"installedSize" cyclonedx:"installedSize"`
	Description   string           `mapstructure:"Description" hash:"ignore" json:"-"`
	Files         []DpkgFileRecord `json:"files"`
}

// DpkgFileRecord represents a single file attributed to a debian package.
type DpkgFileRecord struct {
	Path         string       `json:"path"`
	Digest       *file.Digest `json:"digest,omitempty"`
	IsConfigFile bool         `json:"isConfigFile"`
}

func (m DpkgMetadata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return
}
