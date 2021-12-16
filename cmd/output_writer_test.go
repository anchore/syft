package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOutputWriterConfig(t *testing.T) {
	tmp := t.TempDir() + "/"

	tests := []struct {
		outputs  []string
		file     string
		err      bool
		expected []string
	}{
		{
			outputs:  []string{},
			expected: []string{""},
		},
		{
			outputs:  []string{"json"},
			expected: []string{""},
		},
		{
			file:     "test-1.json",
			expected: []string{"test-1.json"},
		},
		{
			outputs:  []string{"json=test-2.json"},
			expected: []string{"test-2.json"},
		},
		{
			outputs:  []string{"json=test-3-1.json", "spdx-json=test-3-2.json"},
			expected: []string{"test-3-1.json", "test-3-2.json"},
		},
		{
			outputs:  []string{"text", "json=test-4.json"},
			expected: []string{"", "test-4.json"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/%s", test.outputs, test.file), func(t *testing.T) {
			outputs := test.outputs
			for i, val := range outputs {
				outputs[i] = strings.Replace(val, "=", "="+tmp, 1)
			}

			file := test.file
			if file != "" {
				file = tmp + file
			}

			_, err := makeWriter(test.outputs, file)

			if test.err {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			for _, expected := range test.expected {
				if expected != "" {
					assert.FileExists(t, tmp+expected)
				} else if file != "" {
					assert.FileExists(t, file)
				} else {
					assert.NoFileExists(t, expected)
				}
			}
		})
	}
}
