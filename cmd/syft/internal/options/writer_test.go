package options

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/pkg/homedir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/sbom"
)

func Test_MakeSBOMWriter(t *testing.T) {
	tests := []struct {
		name    string
		outputs []string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "go case",
			outputs: []string{"json"},
			wantErr: assert.NoError,
		},
		{
			name:    "multiple",
			outputs: []string{"table", "json"},
			wantErr: assert.NoError,
		},
		{
			name:    "unknown format",
			outputs: []string{"unknown"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, `unsupported output format "unknown", supported formats are:`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := DefaultOutput()
			require.NoError(t, opt.Format.PostLoad())
			encoders, err := opt.Encoders()
			require.NoError(t, err)
			_, err = makeSBOMWriter(tt.outputs, "", encoders)
			tt.wantErr(t, err)
		})
	}
}

func dummyFormat(name string) sbom.FormatEncoder {
	return dummyEncoder{name: name}
}

var _ sbom.FormatEncoder = (*dummyEncoder)(nil)

type dummyEncoder struct {
	name string
}

func (d dummyEncoder) ID() sbom.FormatID {
	return sbom.FormatID(d.name)
}

func (d dummyEncoder) Aliases() []string {
	return nil
}

func (d dummyEncoder) Version() string {
	return sbom.AnyVersion
}

func (d dummyEncoder) Encode(writer io.Writer, s sbom.SBOM) error {
	return nil
}

func Test_newSBOMMultiWriter(t *testing.T) {
	type writerConfig struct {
		format string
		file   string
	}

	tmp := t.TempDir()

	testName := func(options []sbomWriterDescription, err bool) string {
		var out []string
		for _, opt := range options {
			out = append(out, string(opt.Format.ID())+"="+opt.Path)
		}
		errs := ""
		if err {
			errs = "(err)"
		}
		return strings.Join(out, ", ") + errs
	}

	tests := []struct {
		outputs  []sbomWriterDescription
		err      bool
		expected []writerConfig
	}{
		{
			outputs: []sbomWriterDescription{},
			err:     true,
		},
		{
			outputs: []sbomWriterDescription{
				{
					Format: dummyFormat("table"),
					Path:   "",
				},
			},
			expected: []writerConfig{
				{
					format: "table",
				},
			},
		},
		{
			outputs: []sbomWriterDescription{
				{
					Format: dummyFormat("json"),
				},
			},
			expected: []writerConfig{
				{
					format: "json",
				},
			},
		},
		{
			outputs: []sbomWriterDescription{
				{
					Format: dummyFormat("json"),
					Path:   "test-2.json",
				},
			},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-2.json",
				},
			},
		},
		{
			outputs: []sbomWriterDescription{
				{
					Format: dummyFormat("json"),
					Path:   "test-3/1.json",
				},
				{
					Format: dummyFormat("spdx-json"),
					Path:   "test-3/2.json",
				},
			},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-3/1.json",
				},
				{
					format: "spdx-json",
					file:   "test-3/2.json",
				},
			},
		},
		{
			outputs: []sbomWriterDescription{
				{
					Format: dummyFormat("text"),
				},
				{
					Format: dummyFormat("spdx-json"),
					Path:   "test-4.json",
				},
			},
			expected: []writerConfig{
				{
					format: "text",
				},
				{
					format: "spdx-json",
					file:   "test-4.json",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(testName(test.outputs, test.err), func(t *testing.T) {
			outputs := test.outputs
			for i := range outputs {
				if outputs[i].Path != "" {
					outputs[i].Path = tmp + outputs[i].Path
				}
			}

			mw, err := newSBOMMultiWriter(outputs...)

			if test.err {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, mw.writers, len(test.expected))

			for i, e := range test.expected {
				switch w := mw.writers[i].(type) {
				case *sbomStreamWriter:
					assert.Equal(t, string(w.format.ID()), e.format)
					assert.NotNil(t, w.out)
					if e.file != "" {
						assert.FileExists(t, tmp+e.file)
					}
				case *sbomPublisher:
					assert.Equal(t, string(w.format.ID()), e.format)
				default:
					t.Fatalf("unknown writer type: %T", w)
				}

			}
		})
	}
}

func Test_newSBOMWriterDescription(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "expand home dir",
			path:     "~/place.txt",
			expected: filepath.Join(homedir.Get(), "place.txt"),
		},
		{
			name:     "passthrough other paths",
			path:     "/other/place.txt",
			expected: "/other/place.txt",
		},
		{
			name:     "no path",
			path:     "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newSBOMWriterDescription(dummyFormat("table"), tt.path)
			assert.Equal(t, tt.expected, o.Path)
		})
	}
}

func Test_formatVersionOptions(t *testing.T) {

	tests := []struct {
		name             string
		nameVersionPairs []string
		want             string
	}{
		{
			name: "gocase",
			nameVersionPairs: []string{
				"cyclonedx-json@1.2", "cyclonedx-json@1.3", "cyclonedx-json@1.4", "cyclonedx-json@1.5",
				"cyclonedx-xml@1.0", "cyclonedx-xml@1.1", "cyclonedx-xml@1.2", "cyclonedx-xml@1.3",
				"cyclonedx-xml@1.4", "cyclonedx-xml@1.5", "github-json", "spdx-json@2.2", "spdx-json@2.3",
				"spdx-tag-value@2.1", "spdx-tag-value@2.2", "spdx-tag-value@2.3", "syft-json@11.0.0",
				"syft-table", "syft-text", "template",
			},
			want: `
Available formats:
   - cyclonedx-json @ 1.2, 1.3, 1.4, 1.5
   - cyclonedx-xml @ 1.0, 1.1, 1.2, 1.3, 1.4, 1.5
   - github-json
   - spdx-json @ 2.2, 2.3
   - spdx-tag-value @ 2.1, 2.2, 2.3
   - syft-json
   - syft-table
   - syft-text
   - template`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatVersionOptions(tt.nameVersionPairs))
		})
	}
}
