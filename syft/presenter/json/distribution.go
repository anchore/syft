package json

import "github.com/anchore/syft/syft/distro"

// Distribution provides information about a detected Linux Distribution
type Distribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  string `json:"idLike"`
}

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
