package licenses

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/google/licensecheck"
	"github.com/stretchr/testify/require"
)

func TestIdentifyLicenseIDs(t *testing.T) {
	type expectation struct {
		yieldError bool
		ids        []ID
		content    []byte
	}
	tests := []struct {
		name                         string
		in                           string
		includeUnknownLicenseContent bool
		includeFullText              bool
		expected                     expectation
	}{
		{
			name:            "apache license 2.0 with content offset and correct content",
			in:              `test-fixtures/apache-license-2.0`,
			includeFullText: true,
			expected: expectation{
				yieldError: false,
				ids:        []ID{{LicenseID: "Apache-2.0", Offset: Offset{Start: 0, End: 11324}}},
				content:    mustOpen("test-fixtures/apache-license-2.0"),
			},
		},
		{
			name:                         "custom license returns content for IdentifyLicenseIDs",
			in:                           "test-fixtures/nvidia-software-and-cuda-supplement",
			includeUnknownLicenseContent: true,
			expected: expectation{
				yieldError: false,
				ids:        []ID{},
				content:    mustOpen("test-fixtures/nvidia-software-and-cuda-supplement"),
			},
		},
		{
			name:            "Identify multiple license IDs. They should be deduplicated and contain content evidence.",
			in:              `test-fixtures/multi-license`,
			includeFullText: true,
			expected: expectation{
				yieldError: false,
				ids: []ID{
					{LicenseID: "MIT", Offset: Offset{Start: 758, End: 1844}},
					{LicenseID: "NCSA", Offset: Offset{Start: 1925, End: 3463}},
					{LicenseID: "MIT", Offset: Offset{Start: 3708, End: 4932}},
					{LicenseID: "Apache-2.0", Offset: Offset{Start: 5021, End: 16378}},
					{LicenseID: "Zlib", Offset: Offset{Start: 16484, End: 17390}},
					{LicenseID: "Unlicense", Offset: Offset{Start: 17497, End: 18707}},
					{LicenseID: "BSD-2-Clause", Offset: Offset{Start: 18908, End: 20298}},
					{LicenseID: "BSD-3-Clause", Offset: Offset{Start: 20440, End: 21952}},
					{LicenseID: "BSD-2-Clause", Offset: Offset{Start: 22033, End: 23335}},
				},
				content: mustOpen("test-fixtures/multi-license"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content, err := os.ReadFile(test.in)
			require.NoError(t, err)
			ids, content, err := testScanner(test.includeUnknownLicenseContent, test.includeFullText).IdentifyLicenseIDs(context.TODO(), bytes.NewReader(content))
			if test.expected.yieldError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Len(t, ids, len(test.expected.ids))
			require.Len(t, content, len(test.expected.content))

			if len(test.expected.ids) > 0 {
				require.Equal(t, ids, test.expected.ids)
			}

			if len(test.expected.content) > 0 {
				require.Equal(t, content, test.expected.content)
			}
		})
	}
}

func testScanner(includeUnknownLicenseContent, includeFullText bool) Scanner {
	return &scanner{
		coverageThreshold:            DefaultCoverageThreshold,
		includeUnknownLicenseContent: includeUnknownLicenseContent,
		includeFullText:              includeFullText,
		scanner:                      licensecheck.Scan,
	}
}

func mustOpen(fixture string) []byte {
	content, err := os.ReadFile(fixture)
	if err != nil {
		panic(err)
	}

	return content
}
