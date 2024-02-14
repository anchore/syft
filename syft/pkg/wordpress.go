package pkg

// WordpressPluginEntry represents all metadata parsed from the wordpress plugin file
type WordpressPluginEntry struct {
	PluginInstallDirectory string `mapstructure:"pluginInstallDirectory" json:"pluginInstallDirectory"`
	Author                 string `mapstructure:"author" json:"author,omitempty"`
	AuthorURI              string `mapstructure:"authorUri" json:"authorUri,omitempty"`
}
