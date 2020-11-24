package anchore

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

// func TestPackageSbomToModel(t *testing.T) {
// 	tests := []struct {
// 		name string
// 		p    pkg.Package
// 	}{
// 		{
// 			p: pkg.Package{
// 				Name:    "name",
// 				Version: "version",
// 				FoundBy: "foundBy",
// 				Locations: []source.Location{
// 					{
// 						Path:         "path",
// 						FileSystemID: "layerID",
// 					},
// 				},
// 				Licenses: []string{"license"},
// 				Language: pkg.Python,
// 				Type:     pkg.PythonPkg,
// 				CPEs: []pkg.CPE{
// 					must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
// 				},
// 				PURL:         "purl",
// 				MetadataType: pkg.PythonPackageMetadataType,
// 				Metadata: pkg.PythonPackageMetadata{
// 					Name:        "p-name",
// 					Version:     "p-version",
// 					License:     "p-license",
// 					Author:      "p-author",
// 					AuthorEmail: "p-email",
// 					Platform:    "p-platform",
// 					Files: []pkg.PythonFileRecord{
// 						{
// 							Path: "p-path",
// 							Digest: &pkg.PythonFileDigest{
// 								Algorithm: "p-alg",
// 								Value:     "p-digest",
// 							},
// 							Size: "p-size",
// 						},
// 					},
// 					SitePackagesRootPath: "p-site-packages-root",
// 					TopLevelPackages:     []string{"top-level"},
// 				},
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			importer := newPackageSBOMImporter(pkg.NewCatalog(test.p))
// 			model, err := importer.model()
// 			if err != nil {
// 				t.Fatalf("unable to generate model from source material: %+v", err)
// 			}

// 			//fmt.Println(reflect.DeepEqual(model, test.p))
// 			//t.Errorf("sure")

// 		})
// 	}

// }

type mockPackageSBOMImportAPI struct {
	sessionID    string
	model        []external.SyftPackage
	httpResponse *http.Response
	err          error
	ctx          context.Context
}

func (m *mockPackageSBOMImportAPI) ImportImagePackages(ctx context.Context, sessionID string, model []external.SyftPackage) (external.ImageImportContentResponse, *http.Response, error) {
	m.model = model
	m.sessionID = sessionID
	m.ctx = ctx
	return external.ImageImportContentResponse{}, m.httpResponse, m.err
}

func TestPackageSbomImport(t *testing.T) {

	catalog := pkg.NewCatalog(pkg.Package{
		Name:    "name",
		Version: "version",
		FoundBy: "foundBy",
		Locations: []source.Location{
			{
				Path:         "path",
				FileSystemID: "layerID",
			},
		},
		Licenses: []string{"license"},
		Language: pkg.Python,
		Type:     pkg.PythonPkg,
		CPEs: []pkg.CPE{
			must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
		},
		PURL:         "purl",
		MetadataType: pkg.PythonPackageMetadataType,
		Metadata: pkg.PythonPackageMetadata{
			Name:        "p-name",
			Version:     "p-version",
			License:     "p-license",
			Author:      "p-author",
			AuthorEmail: "p-email",
			Platform:    "p-platform",
			Files: []pkg.PythonFileRecord{
				{
					Path: "p-path",
					Digest: &pkg.PythonFileDigest{
						Algorithm: "p-alg",
						Value:     "p-digest",
					},
					Size: "p-size",
				},
			},
			SitePackagesRootPath: "p-site-packages-root",
			TopLevelPackages:     []string{"top-level"},
		},
	})

	theModel, err := toPackageSbomModel(catalog)
	if err != nil {
		t.Fatalf("could not get sbom model: %+v", err)
	}

	sessionID := "my-session"

	tests := []struct {
		name         string
		api          *mockPackageSBOMImportAPI
		expectsError bool
	}{

		// go case: import works (200)
		{
			name: "Go case: import works",
			api: &mockPackageSBOMImportAPI{
				httpResponse: &http.Response{StatusCode: 200},
			},
		},
		// api returns an error
		{
			name: "API returns an error",
			api: &mockPackageSBOMImportAPI{
				err: fmt.Errorf("API error, something went wrong."),
			},
			expectsError: true,
		},
		// api returns no error, but have non-200 http code
		{
			name: "API HTTP-level error",
			api: &mockPackageSBOMImportAPI{
				httpResponse: &http.Response{StatusCode: 404},
			},
			expectsError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			err = generatePackageSbomImporter(context.TODO(), test.api, sessionID, catalog)()

			// validate error handling
			if err != nil && !test.expectsError {
				t.Fatalf("did not expect an error, but got: %+v", err)
			} else if err == nil && test.expectsError {
				t.Fatalf("did expect an error, but got none")
			}

			// validating that the mock got the right parameters (api.ImportImagePackages)
			if test.api.sessionID != sessionID {
				t.Errorf("different session ID: %s != %s", test.api.sessionID, sessionID)
			}

			for _, d := range deep.Equal(test.api.model, theModel) {
				t.Errorf("model difference: %s", d)
			}

		})
	}
}
