package presenter

import (
	"io"
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/presenter/json"
	"github.com/anchore/stereoscope/pkg/image"
)

type Presenter interface {
	Present(io.Writer, *image.Image, pkg.Catalog) error
}

func GetPresenter(userStr string) Presenter {
	switch strings.ToLower(userStr) {
	case JSONOption.String():
		return json.NewPresenter()
	default:
		return nil
	}
}