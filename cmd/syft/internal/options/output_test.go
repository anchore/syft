package options

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/sbom"
)

func Test_getEncoders(t *testing.T) {
	allDefaultEncoderNames := strset.New()
	for _, id := range supportedIDs() {
		allDefaultEncoderNames.Add(id.String())
	}

	opts := DefaultOutput()
	require.NoError(t, opts.Format.PostLoad())
	opts.Format.Template.Path = "somewhere"

	encoders, err := opts.Encoders()
	require.NoError(t, err)
	require.NotEmpty(t, encoders)

	encoderNames := strset.New()
	for _, e := range encoders {
		encoderNames.Add(e.ID().String())
	}

	assert.ElementsMatch(t, allDefaultEncoderNames.List(), encoderNames.List(), "not all encoders are expressed")
}

func Test_EncoderCollection_ByString_IDOnly_Defaults(t *testing.T) {
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
			name: "cdx",
			want: cyclonedxxml.ID,
		},
		{
			name: "cyclone",
			want: cyclonedxxml.ID,
		},
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

	opts := DefaultOutput()
	require.NoError(t, opts.Format.PostLoad())
	opts.Format.Template.Path = "somewhere"

	defaultEncoders, err := opts.Encoders()
	require.NoError(t, err)

	encoders := format.NewEncoderCollection(defaultEncoders...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := encoders.GetByString(tt.name)
			if tt.want == "" {
				require.Nil(t, f)
				return
			}
			require.NotNil(t, f)
			assert.Equal(t, tt.want, f.ID())
		})
	}
}

func Test_OutputHonorsAllowFile(t *testing.T) {
	o := DefaultOutput()

	t.Run("file is not allowed", func(t *testing.T) {
		o.AllowToFile = false
		o.Outputs = []string{"table=/tmp/somefile"}

		w, err := o.SBOMWriter()
		assert.Nil(t, w)
		assert.ErrorContains(t, err, "file output is not allowed")
	})

	t.Run("file is allowed", func(t *testing.T) {
		o.AllowToFile = true
		o.Outputs = []string{"table=/tmp/somefile"}

		w, err := o.SBOMWriter()
		assert.NotNil(t, w)
		assert.NoError(t, err)
	})
}
