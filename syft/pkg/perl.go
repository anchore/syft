package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// CpanDistribution describes a CPAN distribution installed on disk, as recorded by a CPAN client's
// install.json and by the .packlist an installer wrote. There is deliberately no name or version
// field: both would be verbatim copies of the package name and version. Licenses live on the package
// and dependencies live in relationships.
type CpanDistribution struct {
	// Dist is the distvname install.json recorded (e.g. URI-5.35), the raw value the package name and
	// version were recovered from
	Dist string `json:"dist,omitempty"`

	// MainModule is the module name recovered from the .packlist path (e.g. LWP for libwww-perl).
	// Empty when the name came from install.json, which is authoritative. Set, it means the name is the
	// installer's NAME and may not be the distribution name.
	MainModule string `json:"mainModule,omitempty"`

	// Author is the PAUSE ID of the distribution author (e.g. OALDERS), parsed out of Path
	Author string `json:"author,omitempty"`

	// Path is the raw PAUSE path of the release archive (e.g. O/OA/OALDERS/URI-5.35.tar.gz)
	Path string `json:"path,omitempty"`

	// Modules are the modules this distribution provides, sorted by name
	Modules []CpanModule `json:"modules,omitempty"`

	// Files are the paths the .packlist recorded as installed by this distribution, kept in the
	// packlist's own order and unfiltered: a path the packlist claims and the filesystem lacks means the
	// file was removed or overwritten out from under the installer, which is signal rather than noise
	Files []string `json:"files,omitempty"`
}

// OwnedFiles satisfies pkg.FileOwner, so a distribution that installed files a distro package also
// owns is related to it by file ownership rather than reported as an unrelated duplicate.
func (m CpanDistribution) OwnedFiles() (result []string) {
	result = strset.New(m.Files...).List()
	sort.Strings(result)
	return
}

// CpanUnpackedRelease describes an unpacked CPAN release found on disk, read from the release's own
// META.json or META.yml. Weaker evidence than an installed distribution: the code is present but
// nothing says the interpreter can load it. It has no PAUSE path, so it has no author.
type CpanUnpackedRelease struct {
	// Modules are the modules the release declares it provides, sorted by name
	Modules []CpanModule `json:"modules,omitempty"`
}

// CpanModule is a single perl module provided by a CPAN distribution. Shared by both types above.
type CpanModule struct {
	// Name is the module name as it would be used in a perl `use` statement (e.g. URI::Escape)
	Name string `json:"name"`

	// Version is the module version, which may differ from the distribution version
	Version string `json:"version,omitempty"`
}
