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
		ids        []string
		content    []byte
	}
	tests := []struct {
		name     string
		in       string
		expected expectation
	}{
		{
			name: "apache license 2.0",
			in:   `test-fixtures/apache-license-2.0`,
			expected: expectation{
				yieldError: false,
				ids:        []string{"Apache-2.0"},
				content:    nil,
			},
		},
		{
			name: "custom license includes content for IdentifyLicenseIDs",
			in:   "test-fixtures/nvidia-software-and-cuda-supplement",
			expected: expectation{
				yieldError: false,
				ids:        []string{},
				content:    mustOpen("test-fixtures/nvidia-software-and-cuda-supplement"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content, err := os.ReadFile(test.in)
			require.NoError(t, err)
			ids, content, err := testScanner(false).IdentifyLicenseIDs(context.TODO(), bytes.NewReader(content))
			if test.expected.yieldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				require.Len(t, ids, len(test.expected.ids))
				require.Len(t, content, len(test.expected.content))

				if len(test.expected.ids) > 0 {
					require.Equal(t, ids, test.expected.ids)
				}

				if len(test.expected.content) > 0 {
					require.Equal(t, content, test.expected.content)
				}
			}
		})
	}
}

func testScanner(includeLicenseContent bool) Scanner {
	return &scanner{
		coverageThreshold:     DefaultCoverageThreshold,
		includeLicenseContent: includeLicenseContent,
		scanner:               licensecheck.Scan,
	}
}

func mustOpen(fixture string) []byte {
	content, err := os.ReadFile(fixture)
	if err != nil {
		panic(err)
	}

	return content
}
