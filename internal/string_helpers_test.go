package internal

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasAnyOfPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		prefixes []string
		expected bool
	}{
		{
			name:  "go case",
			input: "this has something",
			prefixes: []string{
				"this has",
				"that does not have",
			},
			expected: true,
		},
		{
			name:  "no match",
			input: "this has something",
			prefixes: []string{
				"this DOES NOT has",
				"that does not have",
			},
			expected: false,
		},
		{
			name:     "empty",
			input:    "this has something",
			prefixes: []string{},
			expected: false,
		},
		{
			name:  "positive match last",
			input: "this has something",
			prefixes: []string{
				"that does not have",
				"this has",
			},
			expected: true,
		},
		{
			name:  "empty input",
			input: "",
			prefixes: []string{
				"that does not have",
				"this has",
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, HasAnyOfPrefixes(test.input, test.prefixes...))
		})
	}
}

func TestTruncateMiddleEllipsis(t *testing.T) {
	tests := []struct {
		input    string
		len      int
		expected string
	}{
		{
			input:    "nobody expects the spanish inquisition",
			len:      39,
			expected: "nobody expects the spanish inquisition",
		},
		{
			input:    "nobody expects the spanish inquisition",
			len:      30,
			expected: "nobody expects ...ish inquisition",
		},
		{
			input:    "nobody expects the spanish inquisition",
			len:      38,
			expected: "nobody expects the spanish inquisition",
		},
		{
			input:    "",
			len:      30,
			expected: "",
		},
		{
			input:    "",
			len:      0,
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.input+":"+strconv.Itoa(test.len), func(t *testing.T) {
			assert.Equal(t, test.expected, TruncateMiddleEllipsis(test.input, test.len))
		})
	}
}

func TestSplitAny(t *testing.T) {

	tests := []struct {
		name   string
		input  string
		fields string
		want   []string
	}{
		{
			name:   "simple",
			input:  "a,b,c",
			fields: ",",
			want:   []string{"a", "b", "c"},
		},
		{
			name:   "empty",
			input:  "",
			fields: ",",
			want:   []string{""},
		},
		{
			name:   "multiple separators",
			input:  "a,b\nc:d",
			fields: ",:\n",
			want:   []string{"a", "b", "c", "d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SplitAny(tt.input, tt.fields))
		})
	}
}
