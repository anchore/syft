package javascript

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePnpmLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "nanoid",
			Version:   "3.3.4",
			PURL:      "pkg:npm/nanoid@3.3.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{}},
		},
		{
			Name:      "picocolors",
			Version:   "1.0.0",
			PURL:      "pkg:npm/picocolors@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{}},
		},
		{
			Name:      "source-map-js",
			Version:   "1.0.2",
			PURL:      "pkg:npm/source-map-js@1.0.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{}},
		},
		{
			Name:      "@bcoe/v8-coverage",
			Version:   "0.2.3",
			PURL:      "pkg:npm/%40bcoe/v8-coverage@0.2.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution:   pkg.PnpmLockResolution{Integrity: "sha512-0hYQ8SB4Db5zvZB4axdMHGwEaQjkZzFjQiN9LVYvIFB2nSUHW9tYpxWriPrWDASIxiaXax83REcLxuSdnGPZtw=="},
				Dependencies: map[string]string{},
			},
		},
	}

	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestParsePnpmV6Lock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm-v6/pnpm-lock.yaml"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@testing-library/jest-dom",
			Version:   "5.16.5",
			PURL:      "pkg:npm/%40testing-library/jest-dom@5.16.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-N5ixQ2qKpi5OLYfwQmUb/5mSV9LneAcaUfp32pn4yCnpb8r/Yz0pXFPck21dIicKmi+ta5WRAknkZCfA8refMA=="},
				Dependencies: map[string]string{
					"@adobe/css-tools":                 "4.2.0",
					"@babel/runtime":                   "7.21.0",
					"@types/testing-library__jest-dom": "5.14.5",
					"aria-query":                       "5.1.3",
					"chalk":                            "3.0.0",
					"css.escape":                       "1.5.1",
					"dom-accessibility-api":            "0.5.16",
					"lodash":                           "4.17.21",
					"redent":                           "3.0.0",
				}},
		},
		{
			Name:      "@testing-library/react",
			Version:   "13.4.0",
			PURL:      "pkg:npm/%40testing-library/react@13.4.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-sXOGON+WNTh3MLE9rve97ftaZukN3oNf2KjDy7YTx6hcTO2uuLHuCGynMDhFwGw/jYf4OJ2Qk0i4i79qMNNkyw=="},
				Dependencies: map[string]string{
					"@babel/runtime":       "7.21.0",
					"@testing-library/dom": "8.20.0",
					"@types/react-dom":     "18.2.1",
					"react":                "18.2.0",
					"react-dom":            "18.2.0",
				},
			},
		},
		{
			Name:      "@testing-library/user-event",
			Version:   "13.5.0",
			PURL:      "pkg:npm/%40testing-library/user-event@13.5.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-5Kwtbo3Y/NowpkbRuSepbyMFkZmHgD+vPzYB/RJ4oxt5Gj/avFFBYjhw27cqSVPVw/3a67NK1PbiIr9k4Gwmdg=="},
				Dependencies: map[string]string{
					"@babel/runtime":       "7.21.0",
					"@testing-library/dom": "9.2.0",
				},
			},
		},
		{
			Name:      "react",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-/3IjMdb2L9QbBdWiW5e3P2/npwMBaU9mHCSCUzNln0ZCYbcfTsGbTJrU/kGemdH2IWmB2ioZ+zkxtmq6g09fGQ=="},
				Dependencies: map[string]string{
					"loose-envify": "1.4.0",
				},
			},
		},
		{
			Name:      "react-dom",
			Version:   "18.2.0",
			PURL:      "pkg:npm/react-dom@18.2.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-6IMTriUmvsjHUjNtEDudZfuDQUoWXVxKHhlEGSk81n4YFS+r/Kl99wXiwlVXtPBtJenozv2P+hxDsw9eA7Xo6g=="},
				Dependencies: map[string]string{
					"loose-envify": "1.4.0",
					"react":        "18.2.0",
					"scheduler":    "0.23.0",
				},
			},
		},
		{
			Name:      "web-vitals",
			Version:   "2.1.4",
			PURL:      "pkg:npm/web-vitals@2.1.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution:   pkg.PnpmLockResolution{Integrity: "sha512-sVWcwhU5mX6crfI5Vd2dC4qchyTqxV8URinzt25XqVh+bHEPGH4C3NPrNionCP7Obx59wrYEbNlw4Z8sjALzZg=="},
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "@babel/core",
			Version:   "7.21.4",
			PURL:      "pkg:npm/%40babel/core@7.21.4",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-qt/YV149Jman/6AfmlxJ04LMIu8bMoyl3RB91yTFrxQmgbrSvQMy7cI8Q62FHx1t8wJ8B5fu0UDoLwHAhUo1QA=="},
				Dependencies: map[string]string{
					"@ampproject/remapping":             "2.2.1",
					"@babel/code-frame":                 "7.21.4",
					"@babel/generator":                  "7.21.4",
					"@babel/helper-compilation-targets": "7.21.4",
					"@babel/helper-module-transforms":   "7.21.2",
					"@babel/helpers":                    "7.21.0",
					"@babel/parser":                     "7.21.4",
					"@babel/template":                   "7.20.7",
					"@babel/traverse":                   "7.21.4",
					"@babel/types":                      "7.21.4",
					"convert-source-map":                "1.9.0",
					"debug":                             "4.3.4",
					"gensync":                           "1.0.0-beta.2",
					"json5":                             "2.2.3",
					"semver":                            "6.3.0",
				},
			},
		},
		{
			Name:      "@types/eslint",
			Version:   "8.37.0",
			PURL:      "pkg:npm/%40types/eslint@8.37.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-Piet7dG2JBuDIfohBngQ3rCt7MgO9xCO4xIMKxBThCq5PNRB91IjlJ10eJVwfoNtvTErmxLzwBZ7rHZtbOMmFQ=="},
				Dependencies: map[string]string{
					"@types/estree":      "1.0.1",
					"@types/json-schema": "7.0.11",
				},
			},
		},
		{
			Name:      "read-cache",
			Version:   "1.0.0",
			PURL:      "pkg:npm/read-cache@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-Owdv/Ft7IjOgm/i0xvNDZ1LrRANRfew4b2prF3OWMQLxLfu3bS8FVhCsrSCMK4lR56Y9ya+AThoTpDCTxCmpRA=="},
				Dependencies: map[string]string{
					"pify": "2.3.0",
				},
			},
		},
		{
			Name:      "schema-utils",
			Version:   "3.1.2",
			PURL:      "pkg:npm/schema-utils@3.1.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-pvjEHOgWc9OWA/f/DE3ohBWTD6EleVLf7iFUkoSwAxttdBhB9QUebQgxER2kWueOvRJXPHNnyrvvh9eZINB8Eg=="},
				Dependencies: map[string]string{
					"@types/json-schema": "7.0.11",
					"ajv":                "6.12.6",
					"ajv-keywords":       "3.5.2",
				},
			},
		},
	}
	expectedRelationships = []artifact.Relationship{
		{
			From: expectedPkgs[3],
			To:   expectedPkgs[1],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[3],
			To:   expectedPkgs[4],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[4],
			To:   expectedPkgs[1],
			Type: artifact.DependencyOfRelationship,
		},
	}
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestParsePnpmLockV9(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/pnpm-v9/pnpm-lock.yaml"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "@babel/core",
			Version:   "7.24.7",
			PURL:      "pkg:npm/%40babel/core@7.24.7",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-4RjkiFFI42+268iBv2nC+iMLTJGQW3u9P7YvA3x/6MDrJ9IYZ8I/xx5a2GIhY5gBTOcI4iC5S5in2fGjE+P4Yw=="}},
		},
		{
			Name:      "@babel/helper-plugin-utils",
			Version:   "7.24.7",
			PURL:      "pkg:npm/%40babel/helper-plugin-utils@7.24.7",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-8A2+zKm53/3w4rwbX11FMW/yFS6c5Vam02P/dw01aK6KbwkKqBaIt3eEATiKtn9I2uS1itk8/aZ2yZ/kURee4Q=="}},
		},
		{
			Name:      "is-positive",
			Version:   "3.1.0",
			PURL:      "pkg:npm/is-positive@3.1.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-9ffLCf_f5sopimAhg2g91a7b9Rw5A1aA9eI6S391S3VEzYw99I3iKjcZGxLp25s0cRxNBV5aL2mhn7421SSlA=="}},
		},
		{
			Name:      "rollup",
			Version:   "4.18.0",
			PURL:      "pkg:npm/rollup@4.18.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-QpQY2Q5i0y0Q3RoAvoChE/R5iN2k05N//bNvQbC2XvRjHFT1qWJ2r3n1bNqE+gGRJaeuQf0BxE42D7CyuLh3ZQ=="}},
		},
	}
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	// TODO: no relationships are under test
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expected, expectedRelationships)
}

func TestParsePnpmLockV9WithDependencies(t *testing.T) {
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	fixture := "test-fixtures/pnpm-v9-snapshots/pnpm-lock.yaml"
	locationSet := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "cross-spawn",
			Version:   "7.0.6",
			PURL:      "pkg:npm/cross-spawn@7.0.6",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{
				Resolution: pkg.PnpmLockResolution{Integrity: "sha512-uV2QOWP2nWzsy2aMp8aRibhi9dlzF5Hgh5SHaB9OiTGEyDTiJJyx0uy51QXdyWbtAHNua4XJzUKca3OzKUd3vA=="},
				Dependencies: map[string]string{
					"path-key":        "3.1.1",
					"shebang-command": "2.0.0",
					"which":           "2.0.2",
				},
			},
		},
		{
			Name:      "isexe",
			Version:   "2.0.0",
			PURL:      "pkg:npm/isexe@2.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-RHxMLp9lnKHGHRng9QFhRCMbYAcVpn69smSGcq3f36xjgVVWThj4qqLbTLlq7Ssj8B+fIQ1EuCEGI2lKsyQeIw=="},
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "path-key",
			Version:   "3.1.1",
			PURL:      "pkg:npm/path-key@3.1.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-ojmeN0qd+y0jszEtoY48r0Peq5dwMEkIlCOu6Q5f41lfkswXuKtYrhgoTpLnyIcHm24Uhqx+5Tqm2InSwLhE6Q=="},
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "shebang-command",
			Version:   "2.0.0",
			PURL:      "pkg:npm/shebang-command@2.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-kHxr2zZpYtdmrN1qDjrrX/Z1rR1kG8Dx+gkpK1G4eXmvXswmcE1hTWBWYUzlraYw1/yZp6YuDY77YtvbN0dmDA=="},
				Dependencies: map[string]string{
					"shebang-regex": "3.0.0",
				},
			},
		},
		{
			Name:      "shebang-regex",
			Version:   "3.0.0",
			PURL:      "pkg:npm/shebang-regex@3.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-7++dFhtcx3353uBaq8DDR4NuxBetBzC7ZQOhmTQInHEd6bSrXdiEyzCvG07Z44UYdLShWUyXt5M/yhz8ekcb1A=="},
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "which",
			Version:   "2.0.2",
			PURL:      "pkg:npm/which@2.0.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.PnpmLockEntry{Resolution: pkg.PnpmLockResolution{Integrity: "sha512-BLI3Tl1TW3Pvl70l3yq3Y64i+awpwXqsGBYWkkqMtnbXgrMD+yj7rhW0kuEDxzJaYXGjEW5ogapKNMEKNMjibA=="},
				Dependencies: map[string]string{
					"isexe": "2.0.0",
				},
			},
		},
	}
	expectedRelationships := []artifact.Relationship{
		{
			From: expectedPkgs[1],
			To:   expectedPkgs[5],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[2],
			To:   expectedPkgs[0],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[3],
			To:   expectedPkgs[0],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[4],
			To:   expectedPkgs[3],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[5],
			To:   expectedPkgs[0],
			Type: artifact.DependencyOfRelationship,
		},
	}
	pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, expectedPkgs, expectedRelationships)
}

func TestSearchPnpmForLicenses(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pnpm-remote/pnpm-lock.yaml"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupNpmRegistry()
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
					// https://registry.npmjs.org/nanoid/3.3.4
					path:    "/nanoid/3.3.4",
					handler: generateMockNpmRegistryHandler("test-fixtures/pnpm-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "nanoid",
					Version:   "3.3.4",
					Locations: locations,
					PURL:      "pkg:npm/nanoid@3.3.4",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MIT")),
					Language:  pkg.JavaScript,
					Type:      pkg.NpmPkg,
					Metadata: pkg.PnpmLockEntry{
						Resolution:   pkg.PnpmLockResolution{Integrity: "sha512-MqBkQh/OHTS2egovRtLk45wEyNXwF+cokD+1YPf9u5VfJiRdAiRwB2froX5Co9Rh20xs4siNPm8naNotSD6RBw=="},
						Dependencies: map[string]string{},
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
			tc.config.NPMBaseURL = url
			adapter := newGenericPnpmLockAdapter(tc.config)
			pkgtest.TestFileParser(t, fixture, adapter.parsePnpmLock, tc.expectedPackages, nil)
		})
	}
}
func Test_corruptPnpmLock(t *testing.T) {
	adapter := newGenericPnpmLockAdapter(CatalogerConfig{})
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/pnpm-lock.yaml").
		WithError().
		TestParser(t, adapter.parsePnpmLock)
}

func generateMockNpmRegistryHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Copy the file's content to the response writer
		file, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// setup sets up a test HTTP server for mocking requests to a particular registry.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setupNpmRegistry() (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}
