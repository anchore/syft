package presenter

import (
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/presenter/text"
	"github.com/anchore/syft/syft/scope"
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
