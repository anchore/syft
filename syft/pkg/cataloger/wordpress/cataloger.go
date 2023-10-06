package wordpress

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName        = "wordpress-plugins-cataloger"
	wordpressPluginsGlob = "**/wp-content/plugins/*/*.php"
)

func NewWordpressPluginCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseWordpressPluginFiles, wordpressPluginsGlob)
}
