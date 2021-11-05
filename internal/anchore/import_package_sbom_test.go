package anchore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/formats/syftjson"
	syftjsonModel "github.com/anchore/syft/internal/formats/syftjson/model"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/go-test/deep"
	"github.com/wagoodman/go-progress"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

// this test is tailored towards the assumption that the import doc shape and the syft json shape are the same.
// TODO: replace this as the document shapes diverge.
func TestPackageSbomToModel(t *testing.T) {

	m := source.Metadata{
		Scheme: source.ImageScheme,
		ImageMetadata: source.ImageMetadata{
			UserInput: "user-in",
			Layers: []source.LayerMetadata{
				{
					MediaType: "layer-metadata-type!",
					Digest:    "layer-digest",
					Size:      20,
				},
			},
			Size:           10,
			ManifestDigest: "sha256:digest!",
			MediaType:      "mediatype!",
			Tags:           nil,
		},
	}

	d, _ := distro.NewDistro(distro.CentOS, "8.0", "")

	p := pkg.Package{
		Name:    "name",
		Version: "version",
		FoundBy: "foundBy",
		Locations: []source.Location{
			{
				RealPath:     "path",
				FileSystemID: "layerID",
			},
		},
		Licenses: []string{"license"},
		Language: pkg.Python,
		Type:     pkg.PythonPkg,
		CPEs: []pkg.CPE{
			must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
		},
		PURL: "purl",
	}

	c := pkg.NewCatalog(p)

	model, err := packageSbomModel(m, c, &d)
	if err != nil {
		t.Fatalf("unable to generate model from source material: %+v", err)
	}

	var modelJSON []byte

	modelJSON, err = json.Marshal(&model)
	if err != nil {
		t.Fatalf("unable to marshal model: %+v", err)
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: c,
			Distro:         &d,
		},
		Source: m,
	}

	var buf bytes.Buffer
	pres := syftjson.Format().Presenter(s)
	if err := pres.Present(&buf); err != nil {
		t.Fatalf("unable to get expected json: %+v", err)
	}

	// unmarshal expected result
	var expectedDoc syftjsonModel.Document
	if err := json.Unmarshal(buf.Bytes(), &expectedDoc); err != nil {
		t.Fatalf("unable to parse json doc: %+v", err)
	}

	// unmarshal actual result
	var actualDoc syftjsonModel.Document
	if err := json.Unmarshal(modelJSON, &actualDoc); err != nil {
		t.Fatalf("unable to parse json doc: %+v", err)
	}

	for _, d := range deep.Equal(actualDoc, expectedDoc) {
		if strings.HasSuffix(d, "<nil slice> != []") {
			// do not consider nil vs empty collection semantics as a "difference"
			continue
		}
		t.Errorf("diff: %+v", d)
	}
}

type mockPackageSBOMImportAPI struct {
	sessionID      string
	model          external.ImagePackageManifest
	httpResponse   *http.Response
	err            error
	ctx            context.Context
	responseDigest string
}

func (m *mockPackageSBOMImportAPI) ImportImagePackages(ctx context.Context, sessionID string, model external.ImagePackageManifest) (external.ImageImportContentResponse, *http.Response, error) {
	m.model = model
	m.sessionID = sessionID
	m.ctx = ctx
	if m.httpResponse == nil {
		m.httpResponse = &http.Response{}
	}
	m.httpResponse.Body = ioutils.NewReadCloserWrapper(strings.NewReader(""), func() error { return nil })
	return external.ImageImportContentResponse{Digest: m.responseDigest}, m.httpResponse, m.err
}

func TestPackageSbomImport(t *testing.T) {

	catalog := pkg.NewCatalog(pkg.Package{
		Name:    "name",
		Version: "version",
		FoundBy: "foundBy",
		Locations: []source.Location{
			{
				RealPath:     "path",
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

	m := source.Metadata{
		Scheme: source.ImageScheme,
		ImageMetadata: source.ImageMetadata{
			UserInput:      "user-in",
			Layers:         nil,
			Size:           10,
			ManifestDigest: "sha256:digest!",
			MediaType:      "mediatype!",
			Tags:           nil,
		},
	}

	d, _ := distro.NewDistro(distro.CentOS, "8.0", "")

	theModel, err := packageSbomModel(m, catalog, &d)
	if err != nil {
		t.Fatalf("could not get sbom model: %+v", err)
	}

	sessionID := "my-session"

	tests := []struct {
		name         string
		api          *mockPackageSBOMImportAPI
		expectsError bool
	}{

		{
			name: "Go case: import works",
			api: &mockPackageSBOMImportAPI{
				httpResponse:   &http.Response{StatusCode: 200},
				responseDigest: "digest!",
			},
		},
		{
			name: "API returns an error",
			api: &mockPackageSBOMImportAPI{
				err: fmt.Errorf("API error, something went wrong."),
			},
			expectsError: true,
		},
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

			digest, err := importPackageSBOM(context.TODO(), test.api, sessionID, m, catalog, &d, &progress.Stage{})

			// validate error handling
			if err != nil && !test.expectsError {
				t.Fatalf("did not expect an error, but got: %+v", err)
			} else if err == nil && test.expectsError {
				t.Fatalf("did expect an error, but got none")
			}

			if digest != test.api.responseDigest {
				t.Errorf("unexpected content digest: %q != %q", digest, test.api.responseDigest)
			}

			// validating that the mock got the right parameters (api.ImportImagePackages)
			if test.api.sessionID != sessionID {
				t.Errorf("different session ID: %s != %s", test.api.sessionID, sessionID)
			}

			for _, d := range deep.Equal(&test.api.model, theModel) {
				t.Errorf("model difference: %s", d)
			}

		})
	}
}
