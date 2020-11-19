package json

import "github.com/anchore/syft/syft/distro"

// Distribution provides information about a detected Linux Distribution.
type Distribution struct {
	Name    string `json:"name"`    // Name of the Linux distribution
	Version string `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

// NewDistribution creates a struct with the Linux distribution to be represented in JSON.
func NewDistribution(d *distro.Distro) Distribution {
	if d == nil {
		return Distribution{}
	}

	return Distribution{
		Name:    d.Name(),
		Version: d.FullVersion(),
		IDLike:  d.IDLike,
	}
}
