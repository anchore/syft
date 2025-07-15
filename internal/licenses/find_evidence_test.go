package licenses

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/licensecheck"
	"github.com/stretchr/testify/require"
)

func TestDefaultScanner_FindEvidence(t *testing.T) {
	testCases := []struct {
		name     string
		fixture  string
		wantIDs  []string // expected license IDs
		minMatch int      // minimum # of matches required
	}{
		{
			name:     "Single licenses are able to be recognized and returned Apache 2.0",
			fixture:  "test-fixtures/apache-license-2.0",
			wantIDs:  []string{"Apache-2.0"},
			minMatch: 1,
		},
		{
			name:    "Multiple Licenses are returned as evidence with duplicates at different offset",
			fixture: "test-fixtures/multi-license",
			wantIDs: []string{
				"MIT",
				"MIT",
				"NCSA",
				"Apache-2.0",
				"Zlib",
				"Unlicense",
				"BSD-2-Clause",
				"BSD-2-Clause",
				"BSD-3-Clause",
			},
			minMatch: 2,
		},
	}

	scanner := testScanner()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Clean(tc.fixture)
			f, err := os.Open(filePath)
			require.NoError(t, err)
			defer f.Close()

			evidence, content, err := scanner.FindEvidence(context.Background(), f)
			require.NoError(t, err)
			require.NotEmpty(t, content)
			require.GreaterOrEqual(t, len(evidence), tc.minMatch, "expected at least %d matches", tc.minMatch)

			var foundIDs []string
			for _, ev := range evidence {
				foundIDs = append(foundIDs, ev.ID)
			}

			require.ElementsMatch(t, tc.wantIDs, foundIDs, "expected license IDs %v, but got %v", tc.wantIDs, foundIDs)
		})
	}
}

func testScanner() Scanner {
	return &scanner{
		coverageThreshold: DefaultCoverageThreshold,
		scanner:           licensecheck.Scan,
	}
}

func mustOpen(fixture string) []byte {
	content, err := os.ReadFile(fixture)
	if err != nil {
		panic(err)
	}

	return content
}
