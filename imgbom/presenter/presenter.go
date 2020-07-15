package presenter

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/presenter/json"
	"github.com/anchore/imgbom/imgbom/presenter/text"
	"github.com/anchore/imgbom/imgbom/scope"
)

type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter returns a presenter for images or directories
func GetPresenter(option Option, s scope.Scope, catalog *pkg.Catalog) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(catalog, s)
	case TextPresenter:
		return text.NewPresenter(catalog, s)
	default:
		return nil
	}
}
