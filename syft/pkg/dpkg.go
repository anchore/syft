package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

const DpkgDBGlob = "**/var/lib/dpkg/{status,status.d/**}"

var _ FileOwner = (*DpkgDBEntry)(nil)

// DpkgArchiveEntry represents package metadata extracted from a .deb archive file.
type DpkgArchiveEntry DpkgDBEntry

// DpkgDBEntry represents all captured data for a Debian package DB entry; available fields are described
// at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html in the --showformat section.
// Additional information about how these fields are used can be found at
//   - https://www.debian.org/doc/debian-policy/ch-controlfields.html
//   - https://www.debian.org/doc/debian-policy/ch-relationships.html
//   - https://www.debian.org/doc/debian-policy/ch-binary.html#s-virtual-pkg
//   - https://www.debian.org/doc/debian-policy/ch-relationships.html#s-virtual
type DpkgDBEntry struct {
	// Package is the package name as found in the status file
	Package string `json:"package"`

	// Source is the source package name this binary was built from (one source can produce multiple binary packages)
	Source string `json:"source" cyclonedx:"source"`

	// Version is the binary package version as found in the status file
	Version string `json:"version"`

	// SourceVersion is the source package version (may differ from binary version when binNMU rebuilds occur)
	SourceVersion string `json:"sourceVersion" cyclonedx:"sourceVersion"`

	// Architecture is the target architecture per Debian spec (specific arch like amd64/arm64, wildcard like any, architecture-independent "all", or "source" for source packages)
	Architecture string `json:"architecture"`

	// Maintainer is the package maintainer's name and email in RFC822 format (name must come first, then email in angle brackets)
	Maintainer string `json:"maintainer"`

	// InstalledSize is the total size of installed files in kilobytes
	InstalledSize int `json:"installedSize" cyclonedx:"installedSize"`

	// Description is a human-readable package description with synopsis (first line) and long description (multiline format)
	Description string `hash:"ignore" json:"-"`

	// Provides are the virtual packages provided by this package (allows other packages to depend on capabilities. Can include versioned provides like "libdigest-md5-perl (= 2.55.01)")
	Provides []string `json:"provides,omitempty"`

	// Depends are the packages required for this package to function (will not be installed unless these requirements are met, creates strict ordering constraint)
	Depends []string `json:"depends,omitempty"`

	// PreDepends are the packages that must be installed and configured BEFORE even starting installation of this package (stronger than Depends, discouraged unless absolutely necessary as it adds strict constraints for apt)
	PreDepends []string `json:"preDepends,omitempty"`

	// Files are the files installed by this package
	Files []DpkgFileRecord `json:"files"`
}

// DpkgFileRecord represents a single file attributed to a debian package.
type DpkgFileRecord struct {
	// Path is the file path relative to the filesystem root
	Path string `json:"path"`

	// Digest is the file content hash (typically MD5 for dpkg compatibility with legacy systems)
	Digest *file.Digest `json:"digest,omitempty"`

	// IsConfigFile is whether this file is marked as a configuration file (dpkg will preserve user modifications during upgrades)
	IsConfigFile bool `json:"isConfigFile"`
}

func (m DpkgDBEntry) OwnedFiles() (result []string) {
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
