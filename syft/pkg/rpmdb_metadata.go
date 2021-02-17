package pkg

import (
	"fmt"

	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

var _ fileOwner = (*RpmdbMetadata)(nil)

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

// RpmdbFileRecord represents the file metadata for a single file attributed to a RPM package.
type RpmdbFileRecord struct {
	Path   string        `json:"path"`
	Mode   RpmdbFileMode `json:"mode"`
	Size   int           `json:"size"`
	SHA256 string        `json:"sha256"`
}

// RpmdbFileMode is the raw file mode for a single file. This can be interpreted as the linux stat.h mode (see https://pubs.opengroup.org/onlinepubs/007908799/xsh/sysstat.h.html)
type RpmdbFileMode uint16

// PackageURL returns the PURL for the specific RHEL package (see https://github.com/package-url/purl-spec)
func (m RpmdbMetadata) PackageURL(d *distro.Distro) string {
	if d == nil {
		return ""
	}

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

func (m RpmdbMetadata) ownedFiles() (result []string) {
	for _, f := range m.Files {
		if f.Path != "" {
			result = append(result, f.Path)
		}
	}
	return
}
