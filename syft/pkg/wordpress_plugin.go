package pkg

// WordpressPluginEntry represents all metadata parsed from the wordpress plugin file
type WordpressPluginEntry struct {
	Name      string `mapstructure:"plugin_name" json:"plugin_name"`
	Author    string `mapstructure:"author" json:"author,omitempty"`
	AuthorURI string `mapstructure:"author_uri" json:"author_uri,omitempty"`
}
