package options

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/pkg/homedir"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/sbom"
)

func Test_MakeSBOMWriter(t *testing.T) {
	tests := []struct {
		outputs []string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			outputs: []string{"json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"table", "json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"unknown"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, `unsupported output format "unknown", supported formats are: [`)
			},
		},
	}

	for _, tt := range tests {
		_, err := makeSBOMWriter(tt.outputs, "", "")
		tt.wantErr(t, err)
	}
}

func dummyEncoder(io.Writer, sbom.SBOM) error {
	return nil
}

func dummyFormat(name string) sbom.Format {
	return sbom.NewFormat(sbom.AnyVersion, dummyEncoder, nil, nil, sbom.FormatID(name))
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
