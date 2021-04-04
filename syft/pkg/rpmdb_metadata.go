package pkg

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/syft/syft/file"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

const RpmDbGlob = "**/var/lib/rpm/Packages"

var _ FileOwner = (*RpmdbMetadata)(nil)

// RpmdbMetadata represents all captured data for a RPM DB package entry.
type RpmdbMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Epoch     *int              `json:"epoch"`
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
	Path      string        `json:"path"`
	Mode      RpmdbFileMode `json:"mode"`
	Size      int           `json:"size"`
	Digest    file.Digest   `json:"digest"`
	UserName  string        `json:"userName"`
	GroupName string        `json:"groupName"`
	Flags     string        `json:"flags"`
}

// RpmdbFileMode is the raw file mode for a single file. This can be interpreted as the linux stat.h mode (see https://pubs.opengroup.org/onlinepubs/007908799/xsh/sysstat.h.html)
type RpmdbFileMode uint16

// PackageURL returns the PURL for the specific RHEL package (see https://github.com/package-url/purl-spec)
func (m RpmdbMetadata) PackageURL(d *distro.Distro) string {
	if d == nil {
		return ""
	}

	qualifiers := packageurl.Qualifiers{
		{
			Key:   "arch",
			Value: m.Arch,
		},
	}

	if m.Epoch != nil {
		qualifiers = append(qualifiers,
			packageurl.Qualifier{
				Key:   "epoch",
				Value: strconv.Itoa(*m.Epoch),
			},
		)
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeRPM,
		d.Type.String(),
		m.Name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		fmt.Sprintf("%s-%s", m.Version, m.Release),
		qualifiers,
		"")
	return pURL.ToString()
}

func (m RpmdbMetadata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
