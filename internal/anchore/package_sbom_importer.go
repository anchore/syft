package anchore

import (
	"context"
	"fmt"
	"net/http"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/syft/pkg"
	jsonPresenter "github.com/anchore/syft/syft/presenter/json"
)

var _ Importer = (*PackageSBOMImporter)(nil)

type packageSBOMImporter interface {
	ImportImagePackages(context.Context, string, []external.SyftPackage) (external.ImageImportContentResponse, *http.Response, error)
}

type PackageSBOMImporter struct {
	catalog *pkg.Catalog
}

func NewPackageSBOMImporter(catalog *pkg.Catalog) *PackageSBOMImporter {
	return &PackageSBOMImporter{
		catalog: catalog,
	}
}

// TODO: write test that ensures a 100% match of jsonPresenter.Package to external.SyftPackage with deep.Equals (should work)

func (s PackageSBOMImporter) model() ([]external.SyftPackage, error) {
	var model []external.SyftPackage
	for p := range s.catalog.Enumerate() {
		// the client schema is based on the json presenter, so we should derive all values from this source
		jsonPackage, err := jsonPresenter.NewPackage(p)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize %s: %w", p.String(), err)
		}

		// build locations
		var locations = make([]external.SyftLocation, len(jsonPackage.Locations))
		for i, l := range jsonPackage.Locations {
			locations[i] = external.SyftLocation{
				Path:    l.Path,
				LayerID: l.FileSystemID,
			}
		}

		// create and append the model to the set of models
		model = append(model, external.SyftPackage{
			Name:         jsonPackage.Name,
			Version:      jsonPackage.Version,
			Type:         jsonPackage.Type,
			FoundBy:      jsonPackage.FoundBy,
			Locations:    locations,
			Licenses:     jsonPackage.Licenses,
			Language:     jsonPackage.Language,
			Cpes:         jsonPackage.CPEs,
			Purl:         jsonPackage.PURL,
			MetadataType: jsonPackage.MetadataType,
			Metadata:     jsonPackage.Metadata,
		})
	}
	return model, nil
}

func (s PackageSBOMImporter) doImport(ctx context.Context, sessionID string, api interface{}) error {
	importsApi, ok := api.(packageSBOMImporter)
	if !ok {
		return fmt.Errorf("unrecognized API: %T", api)
	}

	model, err := s.model()
	if err != nil {
		return fmt.Errorf("unable to create PackageSBOMImporter model: %w", err)
	}
	// TODO: are there any useful return values that should be persisted or shown to the user?
	_, _, err = importsApi.ImportImagePackages(ctx, sessionID, model)
	if err != nil {
		return fmt.Errorf("unable to import PackageSBOM: %w", err)
	}
	return nil
}
