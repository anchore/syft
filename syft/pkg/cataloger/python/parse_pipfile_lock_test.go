package python

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePipFileLock(t *testing.T) {

	fixture := "test-fixtures/pipfile-lock/Pipfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "aio-pika",
			Version:   "6.8.0",
			PURL:      "pkg:pypi/aio-pika@6.8.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPipfileLockEntry{
				Index: "https://pypi.org/simple",
				Hashes: []string{
					"sha256:1d4305a5f78af3857310b4fe48348cdcf6c097e0e275ea88c2cd08570531a369",
					"sha256:e69afef8695f47c5d107bbdba21bdb845d5c249acb3be53ef5c2d497b02657c0",
				}},
		},
		{
			Name:      "aiodns",
			Version:   "2.0.0",
			PURL:      "pkg:pypi/aiodns@2.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPipfileLockEntry{
				Index: "https://test.pypi.org/simple",
				Hashes: []string{
					"sha256:815fdef4607474295d68da46978a54481dd1e7be153c7d60f9e72773cd38d77d",
					"sha256:aaa5ac584f40fe778013df0aa6544bf157799bd3f608364b451840ed2c8688de",
				},
			},
		},
		{
			Name:      "aiohttp",
			Version:   "3.7.4.post0",
			PURL:      "pkg:pypi/aiohttp@3.7.4.post0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPipfileLockEntry{
				Index: "https://pypi.org/simple",
				Hashes: []string{
					"sha256:02f46fc0e3c5ac58b80d4d56eb0a7c7d97fcef69ace9326289fb9f1955e65cfe",
					"sha256:0563c1b3826945eecd62186f3f5c7d31abb7391fedc893b7e2b26303b5a9f3fe",
				},
			},
		},
		{
			Name:      "aiohttp-jinja2",
			Version:   "1.4.2",
			PURL:      "pkg:pypi/aiohttp-jinja2@1.4.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPipfileLockEntry{
				Index: "https://pypi.org/simple",
				Hashes: []string{
					"sha256:860da7582efa866744bad5883947557d0f82e457d69903ea65d666b66f8a69ca",
					"sha256:9c22a0e48e3b277fc145c67dd8c3b8f609dab36bce9eb337f70dfe716663c9a0",
				},
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pipfileLockParser := newPipfileLockParser(DefaultCatalogerConfig())
	pkgtest.TestFileParser(t, fixture, pipfileLockParser.parsePipfileLock, expectedPkgs, expectedRelationships)
}

func TestParsePipfileLockWithLicenseEnrichment(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pypi-remote/Pipfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupPypiRegistry()
	defer teardown()
	tests := []struct {
		name             string
		fixture          string
		config           CatalogerConfig
		requestHandlers  []handlerPath
		expectedPackages []pkg.Package
	}{
		{
			name:   "search remote licenses returns the expected licenses when search is set to true",
			config: CatalogerConfig{SearchRemoteLicenses: true},
			requestHandlers: []handlerPath{
				{
					path:    "/certifi/2025.10.5/json",
					handler: generateMockPypiRegistryHandler("test-fixtures/pypi-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "certifi",
					Version:   "2025.10.5",
					Locations: locations,
					PURL:      "pkg:pypi/certifi@2025.10.5",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MPL-2.0")),
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonPipfileLockEntry{
						Index: "https://pypi.org/simple",
						Hashes: []string{
							"sha256:47c09d31ccf2acf0be3f701ea53595ee7e0b8fa08801c6624be771df09ae7b43",
							"sha256:0f212c2744a9bb6de0c56639a6f68afe01ecd92d91f14ae897c4fe7bbeeef0de",
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// set up the mock server
			for _, handler := range tc.requestHandlers {
				mux.HandleFunc(handler.path, handler.handler)
			}
			tc.config.PypiBaseURL = url
			pipfileLockParser := newPipfileLockParser(tc.config)
			pkgtest.TestFileParser(t, fixture, pipfileLockParser.parsePipfileLock, tc.expectedPackages, nil)
		})
	}
}

func Test_corruptPipfileLock(t *testing.T) {
	pipfileLockParser := newPipfileLockParser(DefaultCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/Pipfile.lock").
		WithError().
		TestParser(t, pipfileLockParser.parsePipfileLock)
}
