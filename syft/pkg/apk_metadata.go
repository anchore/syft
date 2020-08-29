package pkg

import (
	"github.com/package-url/packageurl-go"
)

// ApkMetadata represents all captured data for a Alpine DB package entry. See https://wiki.alpinelinux.org/wiki/Apk_spec for more information.
type ApkMetadata struct {
	Package          string          `mapstructure:"P" json:"package"`
	OriginPackage    string          `mapstructure:"o" json:"origin-package"`
	Maintainer       string          `mapstructure:"m" json:"maintainer"`
	Version          string          `mapstructure:"V" json:"version"`
	License          string          `mapstructure:"L" json:"license"`
	Architecture     string          `mapstructure:"A" json:"architecture"`
	URL              string          `mapstructure:"U" json:"url"`
	Description      string          `mapstructure:"T" json:"description"`
	Size             int             `mapstructure:"S" json:"size"`
	InstalledSize    int             `mapstructure:"I" json:"installed-size"`
	PullDependencies string          `mapstructure:"D" json:"pull-dependencies"`
	PullChecksum     string          `mapstructure:"C" json:"pull-checksum"`
	GitCommitOfAport string          `mapstructure:"c" json:"git-commit-of-apk-port"`
	Files            []ApkFileRecord `json:"files"`
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	Path        string `json:"path"`
	OwnerUID    string `json:"owner-uid"`
	OwnerGUI    string `json:"owner-gid"`
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
