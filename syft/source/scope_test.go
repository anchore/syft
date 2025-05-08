package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseScope(t *testing.T) {
	tests := []struct {
		name string
		want Scope
	}{
		// go cases
		{
			name: "squashed",
			want: SquashedScope,
		},
		{
			name: "all-layers",
			want: AllLayersScope,
		},

		{
			name: "deep-squashed",
			want: DeepSquashedScope,
		},
		// fall back to unknown
		{
			name: "make-believe",
			want: UnknownScope,
		},
		{
			name: "",
			want: UnknownScope,
		},
		{
			name: " ",
			want: UnknownScope,
		},
		// to support the original value

		{
			name: "Squashed",
			want: SquashedScope,
		},
		{
			name: "AllLayers",
			want: AllLayersScope,
		},
		// case insensitive
		{
			name: "alLlaYerS",
			want: AllLayersScope,
		},
		// aliases
		{
			name: "all",
			want: AllLayersScope,
		},
		{
			name: "deep-squash",
			want: DeepSquashedScope,
		},
		{
			name: "deepsquashed",
			want: DeepSquashedScope,
		},
		{
			name: "squasheddeep",
			want: DeepSquashedScope,
		},
		{
			name: "squashed-deep",
			want: DeepSquashedScope,
		},
		{
			name: "deepsquash",
			want: DeepSquashedScope,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseScope(tt.name))
		})
	}
}
