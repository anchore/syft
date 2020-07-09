package presenter

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	json_dirs "github.com/anchore/imgbom/imgbom/presenter/json/dirs"
	json_imgs "github.com/anchore/imgbom/imgbom/presenter/json/imgs"
	text_dirs "github.com/anchore/imgbom/imgbom/presenter/text/dirs"
	text_imgs "github.com/anchore/imgbom/imgbom/presenter/text/imgs"
	"github.com/anchore/imgbom/imgbom/scope"
)

type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter returns a presenter for images or directories
func GetPresenter(option Option, s scope.Scope, catalog *pkg.Catalog) Presenter {
	src := s.Source()

	switch src.(type) {
	case scope.DirSource:
		return GetDirPresenter(option, s, catalog)
	case scope.ImageSource:
		return GetImgPresenter(option, s, catalog)
	default:
		return nil
	}
}

// GetImgPresenter returns a Json or Text presenter for images
func GetImgPresenter(option Option, s scope.Scope, c *pkg.Catalog) Presenter {
	src := s.Source()
	img := src.(scope.ImageSource).Img
	switch option {
	case JSONPresenter:
		return json_imgs.NewPresenter(img, c)
	case TextPresenter:
		return text_imgs.NewPresenter(img, c)
	default:
		return nil
	}
}

// GetDirPresenter returns a Json or Text presenter for directories
func GetDirPresenter(option Option, s scope.Scope, c *pkg.Catalog) Presenter {
	src := s.Source()
	path := src.(scope.DirSource).Path
	switch option {
	case JSONPresenter:
		return json_dirs.NewPresenter(c, path)
	case TextPresenter:
		return text_dirs.NewPresenter(c, path)
	default:
		return nil
	}
}
