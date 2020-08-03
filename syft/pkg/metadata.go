package pkg

// Available fields are described at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html
// in the --showformat section
type DpkgMetadata struct {
	Package string `mapstructure:"Package" json:"package"`
	Source  string `mapstructure:"Source" json:"source"`
	Version string `mapstructure:"Version" json:"version"`
	// TODO: consider keeping the remaining values as an embedded map
}

type RpmMetadata struct {
	Epoch   int    `mapstructure:"Epoch" json:"epoch"`
	Arch    string `mapstructure:"Arch" json:"architecture"`
	Release string `mapstructure:"Release" json:"release"`
	// TODO: consider keeping the remaining values as an embedded map
}

type JavaManifest struct {
	Name            string            `mapstructure:"Name" json:"name"`
	ManifestVersion string            `mapstructure:"Manifest-Version" json:"manifest-version"`
	SpecTitle       string            `mapstructure:"Specification-Title" json:"specification-title"`
	SpecVersion     string            `mapstructure:"Specification-Version" json:"specification-version"`
	SpecVendor      string            `mapstructure:"Specification-Vendor" json:"specification-vendor"`
	ImplTitle       string            `mapstructure:"Implementation-Title" json:"implementation-title"`
	ImplVersion     string            `mapstructure:"Implementation-Version" json:"implementation-version"`
	ImplVendor      string            `mapstructure:"Implementation-Vendor" json:"implementation-vendor"`
	Extra           map[string]string `mapstructure:",remain" json:"extra-fields"`
}

type PomProperties struct {
	Path       string
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"group-id"`
	ArtifactID string            `mapstructure:"artifactId" json:"artifact-id"`
	Version    string            `mapstructure:"version" json:"version"`
	Extra      map[string]string `mapstructure:",remain" json:"extra-fields"`
}

type JavaMetadata struct {
	Manifest      *JavaManifest  `mapstructure:"Manifest" json:"manifest"`
	PomProperties *PomProperties `mapstructure:"PomProperties" json:"pom-properties"`
	Parent        *Package       `json:"parent-package"`
}

// source: https://wiki.alpinelinux.org/wiki/Apk_spec
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

type ApkFileRecord struct {
	Path        string `json:"path"`
	OwnerUID    string `json:"owner-uid"`
	OwnerGUI    string `json:"owner-gid"`
	Permissions string `json:"permissions"`
	Checksum    string `json:"checksum"`
}
