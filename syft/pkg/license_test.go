package pkg

import (
	"context"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/stretchr/testify/assert"
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
		values                  []string
		candidates              []Candidate
		contents                []file.LocationReadCloser
		locations               []file.Location
		tp                      license.Type
		expectedValues          []string
		expectedSPDXExpressions []string
		expectedLocations       []file.Location
	}{
		{
			name:                    "single: spdx value returns a license with SPDXExpression populated",
			values:                  []string{"mit"},
			expectedValues:          []string{"mit"},
			expectedSPDXExpressions: []string{"MIT"},
		},
		{
			name:                    "single: value that could be a full license text is converted to content, checked against a scanner, sha256ed, and returned as value",
			values:                  []string{"MIT License\nPermission is hereby granted..."},
			expectedValues:          []string{"LicenseRef-sha256:7f160118c68e1f2548da8d6ebb1bf370b2a61f9a1e0e966a98c479e5d73ff5e4"},
			expectedSPDXExpressions: []string{""},
			expectedLocations:       []file.Location{file.NewLocation("/LICENSE")},
		},
		{
			name: "single: builder with only content is checked against scanner in ctx and returned as a license",
			contents: []file.LocationReadCloser{file.NewLocationReadCloser(
				file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0"),
				mustReadCloser("../../internal/licenses/test-fixtures/apache-license-2.0")),
			},
			expectedValues:          []string{"Apache-2.0"},
			expectedSPDXExpressions: []string{"Apache-2.0"},
			expectedLocations:       []file.Location{file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0")},
		},
		{
			name:   "multiple: builder with multiple candidates and values that overlap return the correct list of licenses with associated locations",
			values: []string{"mit", "0BSD", "Aladdin", "apache-2.0", "BSD-3-Clause-HP"},
			candidates: []Candidate{
				{
					Value: "Apache-2.0",
					Contents: file.NewLocationReadCloser(
						file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0"),
						mustReadCloser("../../internal/licenses/test-fixtures/apache-license-2.0"),
					),
				},
				{
					Value: "BSD-4-Clause",
					Contents: file.NewLocationReadCloser(
						file.NewLocation("../../internal/licenses/test-fixtures/BSD-4-Clause"),
						mustReadCloser("../../internal/licenses/test-fixtures/BSD-4-Clause"),
					),
				},
			},
			// We should get two Apache-2.0 licenses; One from the raw value and one from content analysis
			// We should get 7 licenses total from the builder
			expectedValues:          []string{"mit", "0BSD", "Aladdin", "apache-2.0", "BSD-3-Clause-HP", "Apache-2.0", "BSD-4-Clause"},
			expectedSPDXExpressions: []string{"MIT", "0BSD", "Aladdin", "Apache-2.0", "Apache-2.0", "BSD-3-Clause-HP", "BSD-4-Clause"},
			expectedLocations: []file.Location{
				file.NewLocation("../../internal/licenses/test-fixtures/apache-license-2.0"),
				file.NewLocation("../../internal/licenses/test-fixtures/BSD-4-Clause"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewLicenseBuilder().
				WithCandidates(tt.candidates...).
				WithContents(tt.contents...).
				WithValues(tt.values...)

			result := builder.Build(ctx)
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
