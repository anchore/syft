package r

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractFieldsFromDescriptionFile(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    map[string]string
	}{
		{
			name:    "go case",
			fixture: "test-fixtures/map-parse/simple",
			want: map[string]string{
				"Package":  "base",
				"Version":  "4.3.0",
				"Suggests": "methods",
				"Built":    "R 4.3.0; ; 2023-04-21 11:33:09 UTC; unix",
			},
		},
		{
			name:    "bad cases",
			fixture: "test-fixtures/map-parse/bad",
			want: map[string]string{
				"Key":        "",
				"Whitespace": "",
			},
		},
		{
			name:    "multiline key-value",
			fixture: "test-fixtures/map-parse/multiline",
			want: map[string]string{
				"Description": `A consistent, simple and easy to use set of wrappers around
the fantastic 'stringi' package. All function and argument names (and
positions) are consistent, all functions deal with "NA"'s and zero
length vectors in the same way, and the output from one function is
easy to feed into the input of another.`,
				"License": "MIT + file LICENSE",
				"Key":     "value",
			},
		},
		{
			name:    "eof multiline",
			fixture: "test-fixtures/map-parse/eof-multiline",
			want: map[string]string{
				"License": "MIT + file LICENSE",
				"Description": `A consistent, simple and easy to use set of wrappers around
the fantastic 'stringi' package. All function and argument names (and
positions) are consistent, all functions deal with "NA"'s and zero
length vectors in the same way, and the output from one function is
easy to feed into the input of another.`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open(test.fixture)
			require.NoError(t, err)

			result := extractFieldsFromDescriptionFile(file)

			assert.Equal(t, test.want, result)
		})
	}

}
