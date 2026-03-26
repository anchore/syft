package cataloging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectionRequest_WithExpression(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
		want        SelectionRequest
	}{
		{
			name:        "addition with plus prefix",
			expressions: []string{"+name"},
			want: SelectionRequest{
				AddNames: []string{"name"},
			},
		},
		{
			name:        "removal with minus prefix",
			expressions: []string{"-name"},
			want: SelectionRequest{
				RemoveNamesOrTags: []string{"name"},
			},
		},
		{
			name:        "default selection without prefix",
			expressions: []string{"tag"},
			want: SelectionRequest{
				SubSelectTags: []string{"tag"},
			},
		},
		{
			name:        "mixed operators",
			expressions: []string{"+add, -remove, select"},
			want: SelectionRequest{
				AddNames:          []string{"add"},
				RemoveNamesOrTags: []string{"remove"},
				SubSelectTags:     []string{"select"},
			},
		},
		{
			name:        "comma-separated values in single expression",
			expressions: []string{"a,b,c"},
			want: SelectionRequest{
				SubSelectTags: []string{"a", "b", "c"},
			},
		},
		{
			name:        "whitespace is trimmed",
			expressions: []string{"  +add  , -remove  "},
			want: SelectionRequest{
				AddNames:          []string{"add"},
				RemoveNamesOrTags: []string{"remove"},
			},
		},
		{
			name:        "empty expressions are ignored",
			expressions: []string{"a,,b", "", " , "},
			want: SelectionRequest{
				SubSelectTags: []string{"a", "b"},
			},
		},
		{
			name:        "multiple expression arguments",
			expressions: []string{"+a", "-b", "c"},
			want: SelectionRequest{
				AddNames:          []string{"a"},
				RemoveNamesOrTags: []string{"b"},
				SubSelectTags:     []string{"c"},
			},
		},
		{
			name:        "no expressions returns empty request",
			expressions: nil,
			want:        SelectionRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSelectionRequest().WithExpression(tt.expressions...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSelectionRequest_IsEmpty(t *testing.T) {
	assert.True(t, NewSelectionRequest().IsEmpty())
	assert.False(t, NewSelectionRequest().WithExpression("+a").IsEmpty())
	assert.False(t, NewSelectionRequest().WithExpression("-a").IsEmpty())
	assert.False(t, NewSelectionRequest().WithExpression("a").IsEmpty())
	assert.False(t, NewSelectionRequest().WithDefaults("a").IsEmpty())
}
