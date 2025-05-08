package pkg

import (
	"context"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"os"
	"testing"
)

func TestLicenseBuilder_Build(t *testing.T) {
	ctx := context.Background()
	scanner, _ := licenses.NewDefaultScanner()
	licenses.SetContextLicenseScanner(ctx, scanner)

	tests := []struct {
		name                    string
		value                   string
		contents                file.LocationReadCloser
		locations               file.LocationSet
		tp                      license.Type
		expectedValues          []string
		expectedSPDXExpressions []string
		expectedLocations       []file.Location
	}{
		{
			name:                    "spdx value returns a license with SPDXExpression populated",
			value:                   "mit",
			locations:               file.NewLocationSet(file.NewLocation("/LICENSE")),
			expectedValues:          []string{"mit"},
			expectedSPDXExpressions: []string{"MIT"},
			expectedLocations:       []file.Location{file.NewLocation("/LICENSE")},
		},
		{
			name:                    "value that could be a full license text is converted to content, checked against a scanner, sha256ed, and returned as value",
			value:                   "MIT License\nPermission is hereby granted...",
			locations:               file.NewLocationSet(file.NewLocation("/LICENSE")),
			expectedValues:          []string{"LicenseRef-sha256:7f160118c68e1f2548da8d6ebb1bf370b2a61f9a1e0e966a98c479e5d73ff5e4"},
			expectedSPDXExpressions: []string{""},
			expectedLocations:       []file.Location{file.NewLocation("/LICENSE")},
		},
		{
			name: "builder with only content is checked against scanner in ctx and returned as a license",
			contents: file.NewLocationReadCloser(
				file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0"),
				mustReadCloser("../../internal/licenses/test-fixtures/apache-license-2.0"),
			),
			expectedValues:          []string{"Apache-2.0"},
			expectedSPDXExpressions: []string{"Apache-2.0"},
			expectedLocations:       []file.Location{file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewLicenseBuilder().
				WithContents(tt.contents).
				WithValue(tt.value).
				WithLocations(tt.locations)
			if tt.tp != "" {
				builder = builder.WithType(tt.tp)
			}

			result := builder.Build(ctx)
			require.Len(t, result, len(tt.expectedValues))

			var (
				actualValues          []string
				actualSPDXExpressions []string
				actualLocations       []file.Location
			)
			for _, lic := range result {
				actualValues = append(actualValues, lic.Value)
				actualSPDXExpressions = append(actualSPDXExpressions, lic.SPDXExpression)
				actualLocations = append(actualLocations, lic.Locations.ToSlice()...)

			}
			assert.ElementsMatch(t, tt.expectedSPDXExpressions, actualSPDXExpressions, "SPDX expressions differ")
			assert.ElementsMatch(t, tt.expectedValues, actualValues, "values differ")
			assert.ElementsMatch(t, tt.expectedLocations, actualLocations, "expected locations differ")
		})
	}
}

func mustReadCloser(path string) io.ReadCloser {
	f, err := os.Open(path)
	if err != nil {
		log.Panicf("failed to open file %q: %v", path, err)
	}
	return f
}
