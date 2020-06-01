package imgbom

import (
	"github.com/anchore/imgbom/imgbom/analyzer"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/stereoscope/pkg/image"
)

// TODO: add os detection results as return value
func CatalogImage(img *image.Image, o scope.Option) (*pkg.Catalog, error) {
	s, err := scope.NewScope(img, o)
	if err != nil {
		return nil, err
	}

	// TODO: add OS detection here...

	return analyzer.Analyze(s)
}
