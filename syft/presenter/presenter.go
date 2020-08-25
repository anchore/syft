/*
Defines a Presenter interface for displaying catalog results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package presenter

import (
	"io"

	"github.com/anchore/syft/syft/presenter/cyclonedx"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/presenter/table"
	"github.com/anchore/syft/syft/presenter/text"
	"github.com/anchore/syft/syft/scope"
)

// Presenter defines the expected behavior for an object responsible for displaying arbitrary input and processed data
// to a given io.Writer.
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
	case TablePresenter:
		return table.NewPresenter(catalog, s)
	case CycloneDxPresenter:
		return cyclonedx.NewPresenter(catalog, s)
	default:
		return nil
	}
}
