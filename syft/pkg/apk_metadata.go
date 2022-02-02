package pkg

import (
	"sort"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/scylladb/go-set/strset"
)

const ApkDBGlob = "**/lib/apk/db/installed"

var (
	_ FileOwner     = (*ApkMetadata)(nil)
	_ urlIdentifier = (*ApkMetadata)(nil)
)

// ApkMetadata represents all captured data for a Alpine DB package entry.
// See the following sources for more information:
// - https://wiki.alpinelinux.org/wiki/Apk_spec
// - https://git.alpinelinux.org/apk-tools/tree/src/package.c
// - https://git.alpinelinux.org/apk-tools/tree/src/database.c
type ApkMetadata struct {
	Package          string          `mapstructure:"P" json:"package"`
	OriginPackage    string          `mapstructure:"o" json:"originPackage" cyclonedx:"originPackage"`
	Maintainer       string          `mapstructure:"m" json:"maintainer"`
	Version          string          `mapstructure:"V" json:"version"`
	License          string          `mapstructure:"L" json:"license"`
	Architecture     string          `mapstructure:"A" json:"architecture"`
	URL              string          `mapstructure:"U" json:"url"`
	Description      string          `mapstructure:"T" json:"description"`
	Size             int             `mapstructure:"S" json:"size" cyclonedx:"size"`
	InstalledSize    int             `mapstructure:"I" json:"installedSize" cyclonedx:"installedSize"`
	PullDependencies string          `mapstructure:"D" json:"pullDependencies" cyclonedx:"pullDependencies"`
	PullChecksum     string          `mapstructure:"C" json:"pullChecksum" cyclonedx:"pullChecksum"`
	GitCommitOfAport string          `mapstructure:"c" json:"gitCommitOfApkPort" cyclonedx:"gitCommitOfApkPort"`
	Files            []ApkFileRecord `json:"files"`
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	Path        string       `json:"path"`
	OwnerUID    string       `json:"ownerUid,omitempty"`
	OwnerGID    string       `json:"ownerGid,omitempty"`
	Permissions string       `json:"permissions,omitempty"`
	Digest      *file.Digest `json:"digest,omitempty"`
}

// PackageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func (m ApkMetadata) PackageURL(distro *linux.Release) string {
	qualifiers := map[string]string{
		PURLQualifierArch: m.Architecture,
	}

	if m.OriginPackage != "" {
		qualifiers[PURLQualifierUpstream] = m.OriginPackage
	}

	return packageurl.NewPackageURL(
		// note: this is currently a candidate and not technically within spec
		// see https://github.com/package-url/purl-spec#other-candidate-types-to-define
		"alpine",
		"",
		m.Package,
		m.Version,
		purlQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}

func (m ApkMetadata) OwnedFiles() (result []string) {
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
