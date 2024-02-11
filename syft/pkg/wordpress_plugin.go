package pkg

// WordpressPluginEntry represents all metadata parsed from the wordpress plugin file
type WordpressPluginEntry struct {
	PluginInstallDirectory string `mapstructure:"plugin_install_directory" json:"plugin_install_directory"`
	Author                 string `mapstructure:"author" json:"author,omitempty"`
	AuthorURI              string `mapstructure:"author_uri" json:"author_uri,omitempty"`
}
