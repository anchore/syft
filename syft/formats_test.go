package syft

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/anchore/syft/internal/formats/cyclonedxjson"
	"github.com/anchore/syft/internal/formats/cyclonedxxml"
	"github.com/anchore/syft/internal/formats/github"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
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
			frmt := IdentifyFormat(by)
			assert.NotNil(t, frmt)
			assert.Equal(t, test.expected, frmt.ID())
		})
	}
}

func TestFormats_EmptyInput(t *testing.T) {
	for _, format := range formats {
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

func TestFormatByName(t *testing.T) {

	tests := []struct {
		name string
		want sbom.FormatID
	}{
		// SPDX Tag-Value
		{
			name: "spdx",
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdx-tag-value",
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdx-tv",
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdxtv", // clean variant
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdx-2-tag-value", // clean variant
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdx-2-tagvalue", // clean variant
			want: spdx22tagvalue.ID,
		},
		{
			name: "spdx2-tagvalue", // clean variant
			want: spdx22tagvalue.ID,
		},

		// SPDX JSON
		{
			name: "spdx-json",
			want: spdx22json.ID,
		},
		{
			name: "spdx-2-json",
			want: spdx22json.ID,
		},

		// Cyclonedx JSON
		{
			name: "cyclonedx-json",
			want: cyclonedxjson.ID,
		},
		{
			name: "cyclonedx-1-json",
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
			name: "cyclonedx-1-xml",
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

		// GitHub JSON
		{
			name: "github",
			want: github.ID,
		},

		{
			name: "github-json",
			want: github.ID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := FormatByName(tt.name)
			if tt.want == "" {
				require.Nil(t, f)
				return
			}
			require.NotNil(t, f)
			assert.Equal(t, tt.want, f.ID())
		})
	}
}
