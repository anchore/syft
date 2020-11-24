package anchore

import (
	"context"
	"fmt"
	"net/http"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/syft/pkg"
	jsonPresenter "github.com/anchore/syft/syft/presenter/json"
)

type packageSBOMImportAPI interface {
	ImportImagePackages(context.Context, string, []external.SyftPackage) (external.ImageImportContentResponse, *http.Response, error)
}

// TODO: write test that ensures a 100% match of jsonPresenter.Package to external.SyftPackage with deep.Equals (should work)

func toPackageSbomModel(catalog *pkg.Catalog) ([]external.SyftPackage, error) {
	var model []external.SyftPackage
	for p := range catalog.Enumerate() {
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

func generatePackageSbomImporter(ctx context.Context, api packageSBOMImportAPI, sessionID string, catalog *pkg.Catalog) func() error {
	return func() error {
		model, err := toPackageSbomModel(catalog)
		if err != nil {
			return fmt.Errorf("unable to create PackageSBOM model: %w", err)
		}

		_, httpResponse, err := api.ImportImagePackages(ctx, sessionID, model)
		if err != nil {
			return fmt.Errorf("unable to import PackageSBOM: %w", err)
		}

		if httpResponse.StatusCode != 200 {
			return fmt.Errorf("unable to import PackageSBOM: %s", httpResponse.Status)
		}

		return nil
	}
}
