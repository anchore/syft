package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// /var/lib/rpm/... is the typical path for most distributions
// /usr/share/rpm/... is common for rpm-ostree distributions (coreos-like)
// Packages is the legacy Berkely db based format
// Packages.db is the "ndb" format used in SUSE
// rpmdb.sqlite is the sqlite format used in fedora + derivates
const RpmDBGlob = "**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}"

// Used in CBL-Mariner distroless images
const RpmManifestGlob = "**/var/lib/rpmmanifest/container-manifest-2"

var _ FileOwner = (*RpmMetadata)(nil)

// RpmMetadata represents all captured data for a RPM DB package entry.
type RpmMetadata struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Epoch           *int              `json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`
	Arch            string            `json:"architecture"`
	Release         string            `json:"release" cyclonedx:"release"`
	SourceRpm       string            `json:"sourceRpm" cyclonedx:"sourceRpm"`
	Size            int               `json:"size" cyclonedx:"size"`
	Vendor          string            `json:"vendor"`
	ModularityLabel string            `json:"modularityLabel"`
	Files           []RpmdbFileRecord `json:"files"`
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

func (m RpmMetadata) OwnedFiles() (result []string) {
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
