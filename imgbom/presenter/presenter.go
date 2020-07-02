package presenter

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	json_dirs "github.com/anchore/imgbom/imgbom/presenter/json/dirs"
	json_imgs "github.com/anchore/imgbom/imgbom/presenter/json/imgs"
	text_dirs "github.com/anchore/imgbom/imgbom/presenter/text/dirs"
	text_imgs "github.com/anchore/imgbom/imgbom/presenter/text/imgs"
	"github.com/anchore/stereoscope/pkg/image"
)

type Presenter interface {
	Present(io.Writer) error
}

func GetImgPresenter(option Option, img *image.Image, catalog *pkg.Catalog) Presenter {
	switch option {
	case JSONPresenter:
		return json_imgs.NewPresenter(img, catalog)
	case TextPresenter:
		return text_imgs.NewPresenter(img, catalog)
	default:
		return nil
	}
}

func GetDirPresenter(option Option, path string, catalog *pkg.Catalog) Presenter {
	switch option {
	case JSONPresenter:
		return json_dirs.NewPresenter(catalog, path)
	case TextPresenter:
		return text_dirs.NewPresenter(catalog, path)
	default:
		return nil
	}
}
