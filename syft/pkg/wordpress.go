package pkg

import "github.com/anchore/syft/syft/sort"

// WordpressPluginEntry represents all metadata parsed from the wordpress plugin file
type WordpressPluginEntry struct {
	PluginInstallDirectory string `mapstructure:"pluginInstallDirectory" json:"pluginInstallDirectory"`
	Author                 string `mapstructure:"author" json:"author,omitempty"`
	AuthorURI              string `mapstructure:"authorUri" json:"authorUri,omitempty"`
}

func (p WordpressPluginEntry) Compare(other WordpressPluginEntry) int {
	if i := sort.CompareOrd(p.PluginInstallDirectory, other.PluginInstallDirectory); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Author, other.Author); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.AuthorURI, other.AuthorURI); i != 0 {
		return i
	}
	return 0
}
func (p WordpressPluginEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(WordpressPluginEntry); exists {
		return true, p.Compare(other)
	}
	return false, 0
}
