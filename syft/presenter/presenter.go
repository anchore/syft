/*
Defines a Presenter interface for displaying catalog results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package presenter

import (
	"io"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/presenter/cyclonedx"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/presenter/json"
	"github.com/anchore/syft/syft/presenter/table"
	"github.com/anchore/syft/syft/presenter/text"
	"github.com/anchore/syft/syft/source"
)

// Presenter defines the expected behavior for an object responsible for displaying arbitrary input and processed data
// to a given io.Writer.
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter returns a presenter for images or directories
func GetPresenter(option Option, srcMetadata source.Metadata, catalog *pkg.Catalog, d *distro.Distro) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(catalog, srcMetadata, d)
	case TextPresenter:
		return text.NewPresenter(catalog, srcMetadata)
	case TablePresenter:
		return table.NewPresenter(catalog)
	case CycloneDxPresenter:
		return cyclonedx.NewPresenter(catalog, srcMetadata)
	default:
		return nil
	}
}
