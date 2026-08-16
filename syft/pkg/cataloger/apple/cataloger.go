package apple

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewAppBundleCataloger returns a cataloger for Apple application bundles (.app), reading their Info.plist (CFBundle).
func NewAppBundleCataloger() pkg.Cataloger {
	return generic.NewCataloger("apple-app-bundle-cataloger").
		WithParserByGlobs(parseInfoPlist, "**/*.app/Contents/Info.plist")
}
