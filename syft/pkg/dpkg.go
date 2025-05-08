package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

const DpkgDBGlob = "**/var/lib/dpkg/{status,status.d/**}"

var _ FileOwner = (*DpkgDBEntry)(nil)

type DpkgArchiveEntry DpkgDBEntry

// DpkgDBEntry represents all captured data for a Debian package DB entry; available fields are described
// at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html in the --showformat section.
// Additional information about how these fields are used can be found at
//   - https://www.debian.org/doc/debian-policy/ch-controlfields.html
//   - https://www.debian.org/doc/debian-policy/ch-relationships.html
//   - https://www.debian.org/doc/debian-policy/ch-binary.html#s-virtual-pkg
//   - https://www.debian.org/doc/debian-policy/ch-relationships.html#s-virtual
type DpkgDBEntry struct {
	Package       string `json:"package"`
	Source        string `json:"source" cyclonedx:"source"`
	Version       string `json:"version"`
	SourceVersion string `json:"sourceVersion" cyclonedx:"sourceVersion"`

	// Architecture can include the following sets of values depending on context and the control file used:
	//  - a unique single word identifying a Debian machine architecture as described in Architecture specification string (https://www.debian.org/doc/debian-policy/ch-customized-programs.html#s-arch-spec) .
	//  - an architecture wildcard identifying a set of Debian machine architectures, see Architecture wildcards (https://www.debian.org/doc/debian-policy/ch-customized-programs.html#s-arch-wildcard-spec). any matches all Debian machine architectures and is the most frequently used.
	//  - "all", which indicates an architecture-independent package.
	//  - "source", which indicates a source package.
	Architecture string `json:"architecture"`

	// Maintainer is the package maintainer’s name and email address. The name must come first, then the email
	// address inside angle brackets <> (in RFC822 format).
	Maintainer string `json:"maintainer"`

	InstalledSize int `json:"installedSize" cyclonedx:"installedSize"`

	// Description contains a description of the binary package, consisting of two parts, the synopsis or the short
	// description, and the long description (in a multiline format).
	Description string `hash:"ignore" json:"-"`

	// Provides is a virtual package that is provided by one or more packages. A virtual package is one which appears
	// in the Provides control field of another package. The effect is as if the package(s) which provide a particular
	// virtual package name had been listed by name everywhere the virtual package name appears. (See also Virtual packages)
	Provides []string `json:"provides,omitempty"`

	// Depends This declares an absolute dependency. A package will not be configured unless all of the packages listed in
	// its Depends field have been correctly configured (unless there is a circular dependency).
	Depends []string `json:"depends,omitempty"`

	// PreDepends is like Depends, except that it also forces dpkg to complete installation of the packages named
	// before even starting the installation of the package which declares the pre-dependency.
	PreDepends []string `json:"preDepends,omitempty"`

	Files []DpkgFileRecord `json:"files"`
}

// DpkgFileRecord represents a single file attributed to a debian package.
type DpkgFileRecord struct {
	Path         string       `json:"path"`
	Digest       *file.Digest `json:"digest,omitempty"`
	IsConfigFile bool         `json:"isConfigFile"`
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
