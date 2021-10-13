/*
Defines a Presenter interface for displaying catalog results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package packages

import (
	"github.com/anchore/syft/internal/formats"
	"github.com/anchore/syft/internal/presenter/packages"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/presenter"
)

// Presenter returns a presenter for images or directories
func Presenter(option format.Option, config PresenterConfig) presenter.Presenter {
	switch option {
	case format.TextOption:
		return packages.NewTextPresenter(config.Catalog, config.SourceMetadata)
	case format.TableOption:
		return packages.NewTablePresenter(config.Catalog)
	case format.CycloneDxOption:
		return packages.NewCycloneDxPresenter(config.Catalog, config.SourceMetadata)
	case format.SPDXTagValueOption:
		return packages.NewSPDXTagValuePresenter(config.Catalog, config.SourceMetadata)
	case format.SPDXJSONOption:
		return packages.NewSPDXJSONPresenter(config.Catalog, config.SourceMetadata)
	default:
		// TODO: the final state is that all other cases would be replaced by formats.ByOption (wed remove this function entirely)
		f := formats.ByOption(option)
		if f == nil {
			return nil
		}
		return f.Presenter(config.Catalog, &config.SourceMetadata, config.Distro, config.Scope)
	}
}
