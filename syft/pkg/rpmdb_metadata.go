package pkg

import (
	"fmt"

	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

// RpmdbMetadata represents all captured data for a RPM DB package entry.
type RpmdbMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Epoch     int               `json:"epoch"`
	Arch      string            `json:"architecture"`
	Release   string            `json:"release"`
	SourceRpm string            `json:"sourceRpm"`
	Size      int               `json:"size"`
	License   string            `json:"license"`
	Vendor    string            `json:"vendor"`
	Files     []RpmdbFileRecord `json:"files"`
}

type RpmdbFileRecord struct {
	Path   string        `json:"path"`
	Mode   RpmdbFileMode `json:"mode"`
	Size   int           `json:"size"`
	SHA256 string        `json:"sha256"`
}

type RpmdbFileMode uint16

func (m RpmdbMetadata) PackageURL(d distro.Distro) string {
	pURL := packageurl.NewPackageURL(
		packageurl.TypeRPM,
		d.Type.String(),
		m.Name,
		fmt.Sprintf("%d:%s-%s", m.Epoch, m.Version, m.Release),
		packageurl.Qualifiers{
			{
				Key:   "arch",
				Value: m.Arch,
			},
		},
		"")
	return pURL.ToString()
}
