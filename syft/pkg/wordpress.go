package pkg

// WordpressPluginEntry represents all metadata parsed from the wordpress plugin file
type WordpressPluginEntry struct {
	// PluginInstallDirectory is directory name where the plugin is installed
	PluginInstallDirectory string `mapstructure:"pluginInstallDirectory" json:"pluginInstallDirectory"`

	// Author is plugin author name
	Author string `mapstructure:"author" json:"author,omitempty"`

	// AuthorURI is author's website URL
	AuthorURI string `mapstructure:"authorUri" json:"authorUri,omitempty"`
}
