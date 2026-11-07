package licenses

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/licensecheck"
	"github.com/stretchr/testify/require"
)

func TestScanner_Coverage(t *testing.T) {
	const content = "license text with additional terms"
	match := []licensecheck.Match{{ID: "MIT", Start: 0, End: 12}}
	recognized := []Evidence{{ID: "MIT", End: 12}}
	possible := []Evidence{{ID: "LicenseRef-Possible-MIT-cc91cc0b66ec", End: len(content)}}
	multiple := []licensecheck.Match{{ID: "MIT"}, {ID: "Apache-2.0"}}
	possibleMultiple := []Evidence{possible[0], {ID: "LicenseRef-Possible-Apache-2.0-cc91cc0b66ec", End: len(content)}}
	testCases := []struct {
		name                string
		coverage, threshold float64
		matches             []licensecheck.Match
		want                []Evidence
	}{
		{"unknown gets a descriptive reference", 40, 75, match, possible},
		{"multiple candidates get separate references", 40, 75, multiple, possibleMultiple},
		{"lower threshold still accepts match", 40, 40, match, recognized},
		{"no matches remain unknown", 0, 75, nil, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scanner{coverageThreshold: tc.threshold, scanner: func([]byte) licensecheck.Coverage {
				return licensecheck.Coverage{Percent: tc.coverage, Match: tc.matches}
			}}
			evidence, text, err := s.FindEvidence(context.Background(), strings.NewReader(content))
			require.NoError(t, err)
			require.Equal(t, content, string(text))
			require.ElementsMatch(t, tc.want, evidence)
		})
	}
}

func TestDefaultScanner_FindEvidence(t *testing.T) {
	testCases := []struct {
		name     string
		fixture  string
		wantIDs  []string // expected license IDs
		minMatch int      // minimum # of matches required
	}{
		{
			name:     "Single licenses are able to be recognized and returned Apache 2.0",
			fixture:  "testdata/apache-license-2.0",
			wantIDs:  []string{"Apache-2.0"},
			minMatch: 1,
		},
		{
			name:    "Multiple Licenses are returned as evidence with duplicates at different offset",
			fixture: "testdata/multi-license",
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
