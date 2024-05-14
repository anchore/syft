package r

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_parseDescriptionFile(t *testing.T) {
	type packageAssertions []func(*testing.T, []pkg.Package)
	tests := []struct {
		name       string
		assertions packageAssertions
		fixture    string
	}{
		{
			name:    "no package is returned if no version found",
			fixture: filepath.Join("test-fixtures", "map-parse", "no-version"),
			assertions: packageAssertions{
				func(t *testing.T, p []pkg.Package) {
					assert.Empty(t, p)
				},
			},
		},
		{
			name:    "no package is returned if no package name found",
			fixture: filepath.Join("test-fixtures", "map-parse", "no-name"),
			assertions: packageAssertions{
				func(t *testing.T, p []pkg.Package) {
					assert.Empty(t, p)
				},
			},
		},
		{
			name:    "package return if both name and version found",
			fixture: filepath.Join("test-fixtures", "map-parse", "simple"),
			assertions: packageAssertions{
				func(t *testing.T, p []pkg.Package) {
					assert.Equal(t, 1, len(p))
					assert.Equal(t, "base", p[0].Name)
					assert.Equal(t, "4.3.0", p[0].Version)
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.fixture)
			input := file.LocationReadCloser{
				Location:   file.NewLocation(tt.fixture),
				ReadCloser: f,
			}
			got, _, err := parseDescriptionFile(context.Background(), nil, nil, input)
			assert.NoError(t, err)
			for _, assertion := range tt.assertions {
				assertion(t, got)
			}
		})
	}
}

func Test_extractFieldsFromDescriptionFile(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    map[string]string
	}{
		{
			name:    "go case",
			fixture: "test-fixtures/map-parse/simple",
			want: map[string]string{
				"Package":  "base",
				"Version":  "4.3.0",
				"Suggests": "methods",
				"Built":    "R 4.3.0; ; 2023-04-21 11:33:09 UTC; unix",
			},
		},
		{
			name:    "bad cases",
			fixture: "test-fixtures/map-parse/bad",
			want: map[string]string{
				"Key":        "",
				"Whitespace": "",
			},
		},
		{
			name:    "multiline key-value",
			fixture: "test-fixtures/map-parse/multiline",
			want: map[string]string{
				"Description": `A consistent, simple and easy to use set of wrappers around
the fantastic 'stringi' package. All function and argument names (and
positions) are consistent, all functions deal with "NA"'s and zero
length vectors in the same way, and the output from one function is
easy to feed into the input of another.`,
				"License": "MIT + file LICENSE",
				"Key":     "value",
			},
		},
		{
			name:    "eof multiline",
			fixture: "test-fixtures/map-parse/eof-multiline",
			want: map[string]string{
				"License": "MIT + file LICENSE",
				"Description": `A consistent, simple and easy to use set of wrappers around
the fantastic 'stringi' package. All function and argument names (and
positions) are consistent, all functions deal with "NA"'s and zero
length vectors in the same way, and the output from one function is
easy to feed into the input of another.`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open(test.fixture)
			require.NoError(t, err)

			result := extractFieldsFromDescriptionFile(file)

			assert.Equal(t, test.want, result)
		})
	}

}
