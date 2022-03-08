package syft

import (
	"github.com/anchore/syft/internal/formats/cyclonedx13json"
	"github.com/anchore/syft/internal/formats/cyclonedx13xml"
	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/spdx22tagvalue"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"

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
			want: cyclonedx13json.ID,
		},
		{
			name: "cyclonedx-1-json",
			want: cyclonedx13json.ID,
		},

		// Cyclonedx XML
		{
			name: "cyclonedx",
			want: cyclonedx13xml.ID,
		},
		{
			name: "cyclonedx-xml",
			want: cyclonedx13xml.ID,
		},
		{
			name: "cyclonedx-1-xml",
			want: cyclonedx13xml.ID,
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
