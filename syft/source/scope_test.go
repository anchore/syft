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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseScope(tt.name))
		})
	}
}
