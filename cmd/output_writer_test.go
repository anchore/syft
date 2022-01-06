package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/output"
)

type writerConfig struct {
	format string
	file   string
}

func TestOutputWriterConfig(t *testing.T) {
	dir, err := ioutil.TempDir("", "output-writers-test-")
	assert.NoError(t, err)

	tests := []struct {
		outputs  []string
		file     string
		err      bool
		expected []writerConfig
	}{
		{
			file: "test-1.json",
			expected: []writerConfig{
				{
					format: "table",
					file:   "test-1.json",
				},
			},
		},
		{
			outputs: []string{},
			expected: []writerConfig{
				{
					format: "table",
				},
			},
		},
		{
			outputs: []string{"json"},
			expected: []writerConfig{
				{
					format: "json",
				},
			},
		},
		{
			outputs: []string{"json=test-2.json"},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-2.json",
				},
			},
		},
		{
			outputs: []string{"json=test-3-1.json", "spdx-json=test-3-2.json"},
			expected: []writerConfig{
				{
					format: "json",
					file:   "test-3-1.json",
				},
				{
					format: "spdx-json",
					file:   "test-3-2.json",
				},
			},
		},
		{
			outputs: []string{"text", "json=test-4.json"},
			expected: []writerConfig{
				{
					format: "text",
				},
				{
					format: "json",
					file:   "test-4.json",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/%s", test.outputs, test.file), func(t *testing.T) {
			outputs := test.outputs
			for i, val := range outputs {
				outputs[i] = strings.Replace(val, "=", "="+dir+"/", 1)
			}

			file := test.file
			if file != "" {
				file = dir + "/" + file
			}
			writer, err := makeWriter(test.outputs, file)

			if test.err {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			mw := writer.(*output.MultiWriter)

			assert.Len(t, mw.Writers, len(test.expected))

			for i, e := range test.expected {
				w := mw.Writers[i].(*output.StreamWriter)

				assert.Equal(t, string(w.Format.Option), e.format)

				if e.file != "" {
					assert.NotNil(t, w.Out)
					assert.NotNil(t, w.Closer)
					assert.FileExists(t, dir+"/"+e.file)
				} else {
					assert.Nil(t, w.Closer)
				}
			}
		})
	}
}
