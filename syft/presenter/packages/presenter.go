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
func Presenter(o format.Option, config Config) presenter.Presenter {
	// TODO: This function will be removed in the future
	switch o {
	case format.TextOption:
		return packages.NewTextPresenter(config.Catalog, config.SourceMetadata)
	case format.TableOption:
		return packages.NewTablePresenter(config.Catalog)
	case format.CycloneDxOption:
		return packages.NewCycloneDxPresenter(config.Catalog, config.SourceMetadata)
	case format.SPDXTagValueOption:
		return packages.NewSPDXTagValuePresenter(config.Catalog, config.SourceMetadata)
	default:
		// TODO: this is the new way of getting presenters from formats
		f := formats.ByOption(o)
		if f == nil {
			return nil
		}
		return f.Presenter(config.Catalog, &config.SourceMetadata, config.Distro)
	}
}
