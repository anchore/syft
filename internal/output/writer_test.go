package output

import (
	"strings"
	"testing"

	"github.com/anchore/syft/internal/formats/spdx22json"
	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/internal/formats/text"

	"github.com/stretchr/testify/assert"
)

type writerConfig struct {
	format string
	file   string
}

func TestOutputWriter(t *testing.T) {
	tmp := t.TempDir()

	testName := func(options []WriterOption, err bool) string {
		var out []string
		for _, opt := range options {
			out = append(out, string(opt.Format.Option)+"="+opt.Path)
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
					Format: table.Format(),
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
					Format: syftjson.Format(),
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
					Format: syftjson.Format(),
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
					Format: syftjson.Format(),
					Path:   "test-3/1.json",
				},
				{
					Format: spdx22json.Format(),
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
					Format: text.Format(),
				},
				{
					Format: spdx22json.Format(),
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

			writer, err := MakeWriter(outputs...)

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

				assert.Equal(t, string(w.format.Option), e.format)

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
