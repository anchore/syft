package formats

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/github"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/spdxtagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

func TestIdentify(t *testing.T) {
	tests := []struct {
		fixture  string
		expected sbom.FormatID
	}{
		{
			fixture:  "test-fixtures/alpine-syft.json",
			expected: syftjson.ID,
		},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			assert.NoError(t, err)
			by, err := io.ReadAll(f)
			assert.NoError(t, err)
			frmt := Identify(by)
			assert.NotNil(t, frmt)
			assert.Equal(t, test.expected, frmt.ID())
		})
	}
}

func TestFormats_EmptyInput(t *testing.T) {
	for _, format := range Formats() {
		t.Run(format.ID().String(), func(t *testing.T) {
			t.Run("format.Decode", func(t *testing.T) {
				input := bytes.NewReader(nil)

				assert.NotPanics(t, func() {
					decodedSBOM, err := format.Decode(input)
					assert.Error(t, err)
					assert.Nil(t, decodedSBOM)
				})
			})

			t.Run("format.Validate", func(t *testing.T) {
				input := bytes.NewReader(nil)

				assert.NotPanics(t, func() {
					err := format.Validate(input)
					assert.Error(t, err)
				})
			})
		})
	}
}

func TestByName(t *testing.T) {
	tests := []struct {
		name string
		want sbom.FormatID
	}{
		// SPDX Tag-Value
		{
			name: "spdx",
			want: spdxtagvalue.ID,
		},
		{
			name: "spdx-tag-value",
			want: spdxtagvalue.ID,
		},
		{
			name: "spdx-tv",
			want: spdxtagvalue.ID,
		},
		{
			name: "spdxtv", // clean variant
			want: spdxtagvalue.ID,
		},

		// SPDX JSON
		{
			name: "spdx-json",
			want: spdxjson.ID,
		},
		{
			name: "spdxjson", // clean variant
			want: spdxjson.ID,
		},

		// Cyclonedx JSON
		{
			name: "cyclonedx-json",
			want: cyclonedxjson.ID,
		},
		{
			name: "cyclonedxjson", // clean variant
			want: cyclonedxjson.ID,
		},

		// Cyclonedx XML
		{
			name: "cyclonedx",
			want: cyclonedxxml.ID,
		},
		{
			name: "cyclonedx-xml",
			want: cyclonedxxml.ID,
		},
		{
			name: "cyclonedxxml", // clean variant
			want: cyclonedxxml.ID,
		},

		// Syft Table
		{
			name: "table",
			want: table.ID,
		},
		{
			name: "syft-table",
			want: table.ID,
		},

		// Syft Text
		{
			name: "text",
			want: text.ID,
		},
		{
			name: "syft-text",
			want: text.ID,
		},

		// Syft JSON
		{
			name: "json",
			want: syftjson.ID,
		},
		{
			name: "syft-json",
			want: syftjson.ID,
		},
		{
			name: "syftjson", // clean variant
			want: syftjson.ID,
		},

		// GitHub JSON
		{
			name: "github",
			want: github.ID,
		},
		{
			name: "github-json",
			want: github.ID,
		},

		// Syft template
		{
			name: "template",
			want: template.ID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ByName(tt.name)
			if tt.want == "" {
				require.Nil(t, f)
				return
			}
			require.NotNil(t, f)
			assert.Equal(t, tt.want, f.ID())
		})
	}
}

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
