package sbom

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func dummyEncoder(io.Writer, SBOM) error {
	return nil
}

func dummyFormat(name string) Format {
	return NewFormat(FormatID(name), dummyEncoder, nil, nil)
}

type writerConfig struct {
	format string
	file   string
}

func TestOutputWriter(t *testing.T) {
	tmp := t.TempDir()

	testName := func(options []WriterOption, err bool) string {
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
		outputs  []WriterOption
		err      bool
		expected []writerConfig
	}{
		{
			outputs: []WriterOption{},
			err:     true,
		},
		{
			outputs: []WriterOption{
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
			outputs: []WriterOption{
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
			outputs: []WriterOption{
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
			outputs: []WriterOption{
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
			outputs: []WriterOption{
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

			writer, err := NewWriter(outputs...)

			if test.err {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			mw := writer.(*multiWriter)

			assert.Len(t, mw.writers, len(test.expected))

			for i, e := range test.expected {
				w := mw.writers[i].(*streamWriter)

				assert.Equal(t, string(w.format.ID()), e.format)

				if e.file != "" {
					assert.FileExists(t, tmp+e.file)
				}

				if e.file != "" {
					assert.NotNil(t, w.out)
					assert.NotNil(t, w.close)
				} else {
					assert.NotNil(t, w.out)
					assert.Nil(t, w.close)
				}
			}
		})
	}
}
