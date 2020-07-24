package pkg

// TODO: consider keeping the remaining values as an embedded map
// Available fields are described at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html
// in the --showformat section
type DpkgMetadata struct {
	Package string `mapstructure:"Package"`
	Source  string `mapstructure:"Source"`
	Version string `mapstructure:"Version"`
}

type RpmMetadata struct {
	Epoch   int    `mapstructure:"Epoch"`
	Arch    string `mapstructure:"Arch"`
	Release string `mapstructure:"Release"`
}

type JavaManifest struct {
	Name            string            `mapstructure:"Name"`
	ManifestVersion string            `mapstructure:"Manifest-Version"`
	SpecTitle       string            `mapstructure:"Specification-Title"`
	SpecVersion     string            `mapstructure:"Specification-Version"`
	SpecVendor      string            `mapstructure:"Specification-Vendor"`
	ImplTitle       string            `mapstructure:"Implementation-Title"`
	ImplVersion     string            `mapstructure:"Implementation-Version"`
	ImplVendor      string            `mapstructure:"Implementation-Vendor"`
	Extra           map[string]string `mapstructure:",remain"`
}

type PomProperties struct {
	Path       string
	Name       string            `mapstructure:"name"`
	GroupID    string            `mapstructure:"groupId"`
	ArtifactID string            `mapstructure:"artifactId"`
	Version    string            `mapstructure:"version"`
	Extra      map[string]string `mapstructure:",remain"`
}

type JavaMetadata struct {
	Manifest      *JavaManifest  `mapstructure:"Manifest"`
	PomProperties *PomProperties `mapstructure:"PomProperties"`
	Parent        *Package
}

// source: https://wiki.alpinelinux.org/wiki/Apk_spec
type ApkMetadata struct {
	Package          string `mapstructure:"P"`
	OriginPackage    string `mapstructure:"o"`
	Maintainer       string `mapstructure:"m"`
	Version          string `mapstructure:"V"`
	License          string `mapstructure:"L"`
	Architecture     string `mapstructure:"A"`
	URL              string `mapstructure:"U"`
	Description      string `mapstructure:"T"`
	Size             int    `mapstructure:"S"`
	InstalledSize    int    `mapstructure:"I"`
	PullDependencies string `mapstructure:"D"`
	PullChecksum     string `mapstructure:"C"`
	GitCommitOfAport string `mapstructure:"c"`
	Files            []string
}
