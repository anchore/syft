package python

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			locations := file.NewLocationSet(file.NewLocation(tt.fixture))
			for i := range tt.expected {
				tt.expected[i].Locations = locations
			}
			var expectedRelationships []artifact.Relationship

			pkgtest.TestFileParser(t, tt.fixture, parseSetup, tt.expected, expectedRelationships)
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
