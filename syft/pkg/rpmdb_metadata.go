package pkg

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/scylladb/go-set/strset"
)

const RpmDBGlob = "**/var/lib/rpm/Packages"

var (
	_ FileOwner     = (*RpmdbMetadata)(nil)
	_ urlIdentifier = (*RpmdbMetadata)(nil)
)

// RpmdbMetadata represents all captured data for a RPM DB package entry.
type RpmdbMetadata struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Epoch     *int              `json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`
	Arch      string            `json:"architecture"`
	Release   string            `json:"release" cyclonedx:"release"`
	SourceRpm string            `json:"sourceRpm" cyclonedx:"sourceRpm"`
	Size      int               `json:"size" cyclonedx:"size"`
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
func (m RpmdbMetadata) PackageURL(distro *linux.Release) string {
	var namespace string
	if distro != nil {
		namespace = distro.ID
	}

	qualifiers := map[string]string{
		PURLQualifierArch: m.Arch,
	}

	if m.Epoch != nil {
		qualifiers[PURLQualifierEpoch] = strconv.Itoa(*m.Epoch)
	}

	if m.SourceRpm != "" {
		qualifiers[PURLQualifierUpstream] = m.SourceRpm
	}

	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		namespace,
		m.Name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		fmt.Sprintf("%s-%s", m.Version, m.Release),
		purlQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
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
