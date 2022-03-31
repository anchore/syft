package anchore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/anchore/client-go/pkg/external"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
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

func sbomFixture() sbom.SBOM {
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: pkg.NewCatalog(pkg.Package{
				Name:    "name",
				Version: "version",
				FoundBy: "foundBy",
				Locations: source.NewLocationSet(
					source.Location{
						Coordinates: source.Coordinates{
							RealPath:     "path",
							FileSystemID: "layerID",
						},
					},
				),
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
			}),
			LinuxDistribution: &linux.Release{
				ID:        "centos",
				Version:   "8.0",
				VersionID: "8.0",
				IDLike:    []string{"rhel"},
			},
		},
		Relationships: []artifact.Relationship{
			{
				From: source.NewLocation("/place1"),
				To:   source.NewLocation("/place2"),
				Type: artifact.ContainsRelationship,
			},
		},
		Source: source.Metadata{
			Scheme: source.ImageScheme,
			ImageMetadata: source.ImageMetadata{
				UserInput:      "user-in",
				Layers:         nil,
				Size:           10,
				ManifestDigest: "sha256:digest!",
				MediaType:      "mediatype!",
				Tags:           nil,
			},
		},
	}

}

func TestPackageSbomImport(t *testing.T) {
	sbomResult := sbomFixture()
	theModel, err := packageSbomModel(sbomResult)
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

			digest, err := importPackageSBOM(context.TODO(), test.api, sessionID, sbomResult, &progress.Stage{})

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

type modelAssertion func(t *testing.T, model *external.ImagePackageManifest)

func Test_packageSbomModel(t *testing.T) {
	fix := sbomFixture()

	tests := []struct {
		name   string
		sbom   sbom.SBOM
		traits []modelAssertion
	}{
		{
			name: "distro: has single distro id-like",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					LinuxDistribution: &linux.Release{
						Name: "centos-name",
						ID:   "centos-id",
						IDLike: []string{
							"centos-id-like-1",
						},
						Version:   "version",
						VersionID: "version-id",
					},
				},
			},
			traits: []modelAssertion{
				hasDistroInfo("centos-id", "version-id", "centos-id-like-1"),
			},
		},
		{
			name: "distro: has multiple distro id-like",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					LinuxDistribution: &linux.Release{
						Name: "centos-name",
						ID:   "centos-id",
						IDLike: []string{
							"centos-id-like-1",
							"centos-id-like-2",
						},
						Version:   "version",
						VersionID: "version-id",
					},
				},
			},
			traits: []modelAssertion{
				hasDistroInfo("centos-id", "version-id", "centos-id-like-1"),
			},
		},
		{
			name: "distro: has no distro id-like",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					LinuxDistribution: &linux.Release{
						Name:      "centos-name",
						ID:        "centos-id",
						IDLike:    []string{},
						Version:   "version",
						VersionID: "version-id",
					},
				},
			},
			traits: []modelAssertion{
				hasDistroInfo("centos-id", "version-id", ""),
			},
		},
		{
			name: "distro: has no version-id",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					LinuxDistribution: &linux.Release{
						Name:      "centos-name",
						ID:        "centos-id",
						IDLike:    []string{},
						Version:   "version",
						VersionID: "",
					},
				},
			},
			traits: []modelAssertion{
				hasDistroInfo("centos-id", "version", ""),
			},
		},
		{
			name: "distro: has no id",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					LinuxDistribution: &linux.Release{
						Name:      "centos-name",
						ID:        "",
						IDLike:    []string{},
						Version:   "version",
						VersionID: "version-id",
					},
				},
			},
			traits: []modelAssertion{
				hasDistroInfo("centos-name", "version-id", ""),
			},
		},
		{
			name: "should have expected packages",
			sbom: fix,
			traits: []modelAssertion{
				func(t *testing.T, model *external.ImagePackageManifest) {
					require.Len(t, model.Artifacts, 1)

					modelPkg := model.Artifacts
					modelBytes, err := json.Marshal(&modelPkg)
					require.NoError(t, err)

					fixPkg := syftjson.ToFormatModel(fix).Artifacts
					fixBytes, err := json.Marshal(&fixPkg)
					require.NoError(t, err)

					assert.JSONEq(t, string(fixBytes), string(modelBytes))
				},
			},
		},
		{
			name: "should have expected relationships",
			sbom: fix,
			traits: []modelAssertion{
				func(t *testing.T, model *external.ImagePackageManifest) {
					modelPkg := model.ArtifactRelationships
					modelBytes, err := json.Marshal(&modelPkg)
					require.NoError(t, err)

					fixPkg := syftjson.ToFormatModel(fix).ArtifactRelationships
					fixBytes, err := json.Marshal(&fixPkg)
					require.NoError(t, err)

					assert.JSONEq(t, string(fixBytes), string(modelBytes))
				},
			},
		},
		{
			name: "should have expected schema",
			sbom: fix,
			traits: []modelAssertion{
				func(t *testing.T, model *external.ImagePackageManifest) {
					modelPkg := model.Schema
					modelBytes, err := json.Marshal(&modelPkg)
					require.NoError(t, err)

					fixPkg := syftjson.ToFormatModel(fix).Schema
					fixBytes, err := json.Marshal(&fixPkg)
					require.NoError(t, err)

					assert.JSONEq(t, string(fixBytes), string(modelBytes))
				},
			},
		},
		{
			name: "should have expected descriptor",
			sbom: fix,
			traits: []modelAssertion{
				func(t *testing.T, model *external.ImagePackageManifest) {
					modelPkg := model.Descriptor
					modelBytes, err := json.Marshal(&modelPkg)
					require.NoError(t, err)

					fixPkg := syftjson.ToFormatModel(fix).Descriptor
					fixBytes, err := json.Marshal(&fixPkg)
					require.NoError(t, err)

					assert.JSONEq(t, string(fixBytes), string(modelBytes))
				},
			},
		},
		{
			name: "should have expected source",
			sbom: fix,
			traits: []modelAssertion{
				func(t *testing.T, model *external.ImagePackageManifest) {
					modelPkg := model.Source
					modelBytes, err := json.Marshal(&modelPkg)
					require.NoError(t, err)

					fixPkg := syftjson.ToFormatModel(fix).Source
					fixBytes, err := json.Marshal(&fixPkg)
					require.NoError(t, err)

					assert.JSONEq(t, string(fixBytes), string(modelBytes))
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packageSbomModel(tt.sbom)
			require.NoError(t, err)
			for _, fn := range tt.traits {
				fn(t, got)
			}
		})
	}
}

func hasDistroInfo(name, version, idLike string) modelAssertion {
	return func(t *testing.T, model *external.ImagePackageManifest) {
		assert.Equal(t, name, model.Distro.Name)
		assert.Equal(t, version, model.Distro.Version)
		assert.Equal(t, idLike, model.Distro.IdLike)
	}
}
