package pkg

import (
	"fmt"

	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

// RpmMetadata represents all captured data for a RPM DB package entry.
type RpmMetadata struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Epoch     int    `json:"epoch"`
	Arch      string `json:"architecture"`
	Release   string `json:"release"`
	SourceRpm string `json:"source-rpm"`
	Size      int    `json:"size"`
	License   string `json:"license"`
	Vendor    string `json:"vendor"`
}

func (m RpmMetadata) PackageURL(d distro.Distro) string {
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
