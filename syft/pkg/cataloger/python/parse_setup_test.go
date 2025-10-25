package python

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseSetup(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/setup/setup.py",
			expected: []pkg.Package{
				{
					Name:     "pathlib3",
					Version:  "2.2.0",
					PURL:     "pkg:pypi/pathlib3@2.2.0",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "mypy",
					Version:  "v0.770",
					PURL:     "pkg:pypi/mypy@v0.770",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "mypy1",
					Version:  "v0.770",
					PURL:     "pkg:pypi/mypy1@v0.770",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "mypy2",
					Version:  "v0.770",
					PURL:     "pkg:pypi/mypy2@v0.770",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "mypy3",
					Version:  "v0.770",
					PURL:     "pkg:pypi/mypy3@v0.770",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
			},
		},
		{
			// regression... ensure we clean packages names and don't find "%s" as the name
			fixture:  "test-fixtures/setup/dynamic-setup.py",
			expected: nil,
		},
		{
			fixture: "test-fixtures/setup/multiline-split-setup.py",
			expected: []pkg.Package{
				{
					Name:     "black",
					Version:  "23.12.1",
					PURL:     "pkg:pypi/black@23.12.1",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "cairosvg",
					Version:  "2.7.1",
					PURL:     "pkg:pypi/cairosvg@2.7.1",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "celery",
					Version:  "5.3.4",
					PURL:     "pkg:pypi/celery@5.3.4",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "django",
					Version:  "4.2.23",
					PURL:     "pkg:pypi/django@4.2.23",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "mypy",
					Version:  "1.7.1",
					PURL:     "pkg:pypi/mypy@1.7.1",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "pillow",
					Version:  "11.0.0",
					PURL:     "pkg:pypi/pillow@11.0.0",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "pytest",
					Version:  "7.4.3",
					PURL:     "pkg:pypi/pytest@7.4.3",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURL:     "pkg:pypi/requests@2.31.0",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
			},
		},
		{
			// Test mixed quoted and unquoted dependencies - ensure no duplicates
			fixture: "test-fixtures/setup/mixed-format-setup.py",
			expected: []pkg.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURL:     "pkg:pypi/requests@2.31.0",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "django",
					Version:  "4.2.23",
					PURL:     "pkg:pypi/django@4.2.23",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
				{
					Name:     "flask",
					Version:  "3.0.0",
					PURL:     "pkg:pypi/flask@3.0.0",
					Language: pkg.Python,
					Type:     pkg.PythonPkg,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			locations := file.NewLocationSet(file.NewLocation(tt.fixture))
			for i := range tt.expected {
				tt.expected[i].Locations = locations
			}
			var expectedRelationships []artifact.Relationship

			setupFileParser := newSetupFileParser(DefaultCatalogerConfig())
			pkgtest.TestFileParser(t, tt.fixture, setupFileParser.parseSetupFile, tt.expected, expectedRelationships)
		})
	}

}

func TestParseSetupFileWithLicenseEnrichment(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pypi-remote/setup.py"
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
			setupFileParser := newSetupFileParser(tc.config)
			pkgtest.TestFileParser(t, fixture, setupFileParser.parseSetupFile, tc.expectedPackages, nil)
		})
	}
}
func Test_hasTemplateDirective(t *testing.T) {

	tests := []struct {
		input string
		want  bool
	}{
		{
			input: "foo",
			want:  false,
		},
		{
			input: "foo %s",
			want:  true,
		},
		{
			input: "%s",
			want:  true,
		},
		{
			input: "{f_string}",
			want:  true,
		},
		{
			input: "{}", // .format() directive
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, hasTemplateDirective(tt.input))
		})
	}
}
