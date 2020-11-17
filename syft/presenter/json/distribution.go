package json

import "github.com/anchore/syft/syft/distro"

// Distribution provides information about a detected Linux Distribution.
type Distribution struct {
	Name    string `json:"name"`    // Name of the Linux distribution
	Version string `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

// NewDistribution creates a struct with the Linux distribution to be represented in JSON.
func NewDistribution(d distro.Distro) Distribution {
	distroName := d.Name()
	if distroName == "UnknownDistroType" {
		distroName = ""
	}

	return Distribution{
		Name:    distroName,
		Version: d.FullVersion(),
		IDLike:  d.IDLike,
	}
}
