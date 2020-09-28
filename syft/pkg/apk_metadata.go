package pkg

import (
	"github.com/package-url/packageurl-go"
)

// ApkMetadata represents all captured data for a Alpine DB package entry.
// See the following sources for more information:
// - https://wiki.alpinelinux.org/wiki/Apk_spec
// - https://git.alpinelinux.org/apk-tools/tree/src/package.c
// - https://git.alpinelinux.org/apk-tools/tree/src/database.c
type ApkMetadata struct {
	Package          string          `mapstructure:"P" json:"package"`
	OriginPackage    string          `mapstructure:"o" json:"originPackage"`
	Maintainer       string          `mapstructure:"m" json:"maintainer"`
	Version          string          `mapstructure:"V" json:"version"`
	License          string          `mapstructure:"L" json:"license"`
	Architecture     string          `mapstructure:"A" json:"architecture"`
	URL              string          `mapstructure:"U" json:"url"`
	Description      string          `mapstructure:"T" json:"description"`
	Size             int             `mapstructure:"S" json:"size"`
	InstalledSize    int             `mapstructure:"I" json:"installedSize"`
	PullDependencies string          `mapstructure:"D" json:"pullDependencies"`
	PullChecksum     string          `mapstructure:"C" json:"pullChecksum"`
	GitCommitOfAport string          `mapstructure:"c" json:"gitCommitOfApkPort"`
	Files            []ApkFileRecord `json:"files"`
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	Path        string `json:"path"`
	OwnerUID    string `json:"ownerUid"`
	OwnerGUI    string `json:"ownerGid"`
	Permissions string `json:"permissions"`
	Checksum    string `json:"checksum"`
}

func (m ApkMetadata) PackageURL() string {
	pURL := packageurl.NewPackageURL(
		// note: this is currently a candidate and not technically within spec
		// see https://github.com/package-url/purl-spec#other-candidate-types-to-define
		"alpine",
		"",
		m.Package,
		m.Version,
		packageurl.Qualifiers{
			{
				Key:   "arch",
				Value: m.Architecture,
			},
		},
		"")
	return pURL.ToString()
}
