package internal

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchCaptureGroups(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  string
		expected map[string]string
	}{
		{
			name:    "go-case",
			input:   "match this thing",
			pattern: `(?P<name>match).*(?P<version>thing)`,
			expected: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "only matches the first instance",
			input:   "match this thing batch another think",
			pattern: `(?P<name>[mb]atch).*?(?P<version>thin[gk])`,
			expected: map[string]string{
				"name":    "match",
				"version": "thing",
			},
		},
		{
			name:    "nested capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups",
			input:   "cool something to match against",
			pattern: `((?P<name>match) (?P<version>against))?`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
		{
			name:    "nested optional capture groups with larger match",
			input:   "cool something to match against match never",
			pattern: `.*?((?P<name>match) (?P<version>(against|never)))?`,
			expected: map[string]string{
				"name":    "match",
				"version": "against",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := MatchNamedCaptureGroups(regexp.MustCompile(test.pattern), test.input)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestMatchNamedCaptureGroupsFromReader(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    map[string]string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "match single group",
			pattern: `(?P<key>[^1-9]+)`,
			input:   "key",
			want:    map[string]string{"key": "key"},
			wantErr: require.NoError,
		},
		{
			name:    "match multiple groups",
			pattern: `(?P<key>[^1-9]+):(?P<value>\w+)`,
			input:   "key:value",
			want:    map[string]string{"key": "key", "value": "value"},
			wantErr: require.NoError,
		},
		{
			name:    "no match",
			pattern: `(?P<key>[^1-9]+)`,
			input:   "2345",
			want:    nil,
			wantErr: require.NoError,
		},
		{
			name:    "error empty reader",
			pattern: `(?P<key>\w+)`,
			input:   "",
			want:    nil,
			wantErr: require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(tt.pattern)
			r := strings.NewReader(tt.input)
			got, err := MatchNamedCaptureGroupsFromReader(re, r)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchAnyFromReader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		patterns []*regexp.Regexp
		want     bool
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "match single pattern",
			input:    "hello world",
			patterns: []*regexp.Regexp{regexp.MustCompile(`hello`)},
			want:     true,
			wantErr:  require.NoError,
		},
		{
			name:     "match multiple patterns",
			input:    "test case",
			patterns: []*regexp.Regexp{regexp.MustCompile(`case`), regexp.MustCompile(`test`)},
			want:     true,
			wantErr:  require.NoError,
		},
		{
			name:     "no match",
			input:    "nothing here",
			patterns: []*regexp.Regexp{regexp.MustCompile(`absent`)},
			want:     false,
			wantErr:  require.NoError,
		},
		{
			name:     "error empty reader",
			input:    "",
			patterns: []*regexp.Regexp{regexp.MustCompile(`match`)},
			want:     false,
			wantErr:  require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			got, err := MatchAnyFromReader(r, tt.patterns...)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProcessReaderInChunks_ChunkBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		chunkSize     int
		expectedCalls []string
		returnOnChunk int
		wantErr       require.ErrorAssertionFunc
	}{
		{
			name:          "go case",
			input:         "123456789012345",
			chunkSize:     4,
			returnOnChunk: 2,
			expectedCalls: []string{"1234", "345678", "789012"},
			wantErr:       require.NoError,
		},
		{
			name:          "no match",
			input:         "123456789012345",
			chunkSize:     4,
			returnOnChunk: -1,
			expectedCalls: []string{"1234", "345678", "789012", "12345"},
			wantErr:       require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualCalls []string
			var current int
			handler := func(data []byte) (bool, error) {
				actualCalls = append(actualCalls, string(data))
				if current == tt.returnOnChunk {
					return true, nil
				}
				current++
				return false, nil
			}
			r := strings.NewReader(tt.input)
			got, err := processReaderInChunks(r, tt.chunkSize, handler)
			tt.wantErr(t, err)
			if tt.returnOnChunk == -1 {
				assert.False(t, got)
			} else {
				assert.True(t, got)
			}
			assert.Equal(t, tt.expectedCalls, actualCalls)
		})
	}
}
