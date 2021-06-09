/*
Defines a Presenter interface for displaying catalog results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package packages

import (
	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/syft/presenter"
)

// Presenter returns a presenter for images or directories
func Presenter(option PresenterOption, config PresenterConfig) presenter.Presenter {
	switch option {
	case JSONPresenterOption:
		return packages.NewJSONPresenter(config.Catalog, config.SourceMetadata, config.Distro, config.Scope)
	case TextPresenterOption:
		return packages.NewTextPresenter(config.Catalog, config.SourceMetadata)
	case TablePresenterOption:
		return packages.NewTablePresenter(config.Catalog)
	case CycloneDxPresenterOption:
		return packages.NewCycloneDxPresenter(config.Catalog, config.SourceMetadata)
	default:
		return nil
	}
}
