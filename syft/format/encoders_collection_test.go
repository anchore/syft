package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/sbom"
)

func Test_versionMatches(t *testing.T) {
	tests := []struct {
		name    string
		version string
		match   string
		matches bool
	}{
		{
			name:    "any version matches number",
			version: string(sbom.AnyVersion),
			match:   "6",
			matches: true,
		},
		{
			name:    "number matches any version",
			version: "6",
			match:   string(sbom.AnyVersion),
			matches: true,
		},
		{
			name:    "same number matches",
			version: "3",
			match:   "3",
			matches: true,
		},
		{
			name:    "same major number matches",
			version: "3.1",
			match:   "3",
			matches: true,
		},
		{
			name:    "same minor number matches",
			version: "3.1",
			match:   "3.1",
			matches: true,
		},
		{
			name:    "wildcard-version matches minor",
			version: "7.1.3",
			match:   "7.*",
			matches: true,
		},
		{
			name:    "wildcard-version matches patch",
			version: "7.4.8",
			match:   "7.4.*",
			matches: true,
		},
		{
			name:    "sub-version matches major",
			version: "7.19.11",
			match:   "7",
			matches: true,
		},
		{
			name:    "sub-version matches minor",
			version: "7.55.2",
			match:   "7.55",
			matches: true,
		},
		{
			name:    "sub-version matches patch",
			version: "7.32.6",
			match:   "7.32.6",
			matches: true,
		},
		// negative tests
		{
			name:    "different number does not match",
			version: "3",
			match:   "4",
			matches: false,
		},
		{
			name:    "sub-version doesn't match major",
			version: "7.2.5",
			match:   "8.2.5",
			matches: false,
		},
		{
			name:    "sub-version doesn't match minor",
			version: "7.2.9",
			match:   "7.1",
			matches: false,
		},
		{
			name:    "sub-version doesn't match patch",
			version: "7.32.6",
			match:   "7.32.5",
			matches: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := versionMatches(test.version, test.match)
			assert.Equal(t, test.matches, matches)
		})
	}
}

func Test_EncoderCollection_Get(t *testing.T) {
	tests := []struct {
		name            string
		searchName      string
		searchVersion   string
		expectedID      sbom.FormatID
		expectedVersion string
	}{
		{
			name:            "explicit name and version",
			searchName:      "spdx-json",
			searchVersion:   "2.3",
			expectedID:      spdxutil.JSONFormatID,
			expectedVersion: "2.3",
		},
		{
			name:            "explicit name without version gets default",
			searchName:      "spdx-json",
			searchVersion:   "",
			expectedID:      spdxutil.JSONFormatID,
			expectedVersion: "2.3",
		},
		{
			name:            "alias name with version",
			searchName:      "spdx",
			searchVersion:   "2.2",
			expectedID:      spdxutil.TagValueFormatID,
			expectedVersion: "2.2",
		},
		{
			name:            "alias name without version gets default",
			searchName:      "spdx",
			searchVersion:   "",
			expectedID:      spdxutil.TagValueFormatID,
			expectedVersion: "2.3",
		},
		{
			name:          "invalid name gets nothing",
			searchName:    "json-spdx",
			searchVersion: "2.3",
			expectedID:    "",
		},
		{
			name:          "invalid version gets nothing",
			searchName:    "spdx-json",
			searchVersion: "2.0",
			expectedID:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultEncodersConfig()
			// ensure SPDX default is 2.3 for test
			config.SPDXJSON.DefaultVersion = "2.3"
			encoders, err := config.Encoders()
			require.NoError(t, err)
			collection := NewEncoderCollection(encoders...)
			result := collection.Get(test.searchName, test.searchVersion)

			if test.expectedID != "" {
				require.NotNil(t, result, "expected to find encoder but got nil")
				if result != nil {
					require.Equal(t, test.expectedID, result.ID())
					require.Equal(t, test.expectedVersion, result.Version())
				}
			} else {
				require.Nil(t, result, "expected nil but found encoder")
			}
		})
	}
}
