package presenter

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/presenter/json"
	"github.com/anchore/imgbom/imgbom/presenter/text"
	"github.com/anchore/stereoscope/pkg/image"
)

type Presenter interface {
	Present(io.Writer) error
}

func GetPresenter(option Option, img *image.Image, catalog *pkg.Catalog) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(img, catalog)
	case TextPresenter:
		return text.NewPresenter(img, catalog)

	default:
		return nil
	}
}
