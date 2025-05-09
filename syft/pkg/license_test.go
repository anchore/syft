package pkg

import (
	"context"
	"io"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

func TestLicenseBuilder_Build(t *testing.T) {
	ctx := context.Background()
	scanner, err := licenses.NewDefaultScanner()
	if err != nil {
		t.Fatal(err)
	}
	ctx = licenses.SetContextLicenseScanner(ctx, scanner)
	tests := []struct {
		name                    string
		values                  []string
		candidates              []LicenseCandidate
		contents                []file.LocationReadCloser
		locations               []file.Location
		tp                      license.Type
		expectedValues          []string
		expectedSPDXExpressions []string
		expectedLocations       []file.Location
	}{
		{
			name:                    "empty builder should return empty list",
			expectedValues:          []string{},
			expectedSPDXExpressions: []string{},
			expectedLocations:       []file.Location{},
		},
		{
			name:                    "single: spdx value returns a license with SPDXExpression populated",
			values:                  []string{"mit"},
			expectedValues:          []string{"mit"},
			expectedSPDXExpressions: []string{"MIT"},
		},
		{
			name: "single: candidate with metadata location correctly adds location",
			candidates: []LicenseCandidate{
				{
					Value:     "mit",
					Locations: []file.Location{file.NewLocation("/SomeMetadata")},
				},
			},
			expectedValues:          []string{"mit"},
			expectedSPDXExpressions: []string{"MIT"},
			expectedLocations:       []file.Location{file.NewLocation("/SomeMetadata")},
		},
		{
			name:                    "single: candidate with no value is not valid",
			values:                  []string{""},
			expectedValues:          []string{},
			expectedSPDXExpressions: []string{},
			expectedLocations:       []file.Location{},
		},
		{
			name:                    "single: value that could be a full license text is converted to content, checked against a scanner, sha256ed, and returned as value",
			values:                  []string{"MIT License\nPermission is hereby granted..."},
			expectedValues:          []string{"LicenseRef-sha256:7f160118c68e1f2548da8d6ebb1bf370b2a61f9a1e0e966a98c479e5d73ff5e4"},
			expectedSPDXExpressions: []string{""},
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
			// This is important for the bitnami folks who sometimes include both in their packages
			name: "multiple: candidates with different types but similar values are not deduplicated",
			candidates: []LicenseCandidate{
				{Value: "mit", Type: license.Declared},
				{Value: "mit", Type: license.Concluded},
			},
			expectedValues:          []string{"mit", "mit"},
			expectedSPDXExpressions: []string{"MIT", "MIT"},
		},
		{
			// we expect to get 7 licenses from this - the set should not deduplicate any of these
			name:   "multiple: builder with multiple candidates and values that overlap return the correct list of licenses with associated locations",
			values: []string{"mit", "0BSD", "Aladdin", "apache-2.0", "BSD-3-Clause-HP"},
			candidates: []LicenseCandidate{
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
			for _, lic := range result.ToSlice() {
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
