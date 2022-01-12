package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDLikes_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		data     interface{}
		expected IDLikes
	}{
		{
			name: "single string",
			data: "well hello there!",
			expected: IDLikes{
				"well hello there!",
			},
		},
		{
			name: "multiple strings",
			data: []string{
				"well hello there!",
				"...hello there, john!",
			},
			expected: IDLikes{
				"well hello there!",
				"...hello there, john!",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(&tt.data)
			require.NoError(t, err)

			var obj IDLikes
			require.NoError(t, json.Unmarshal(data, &obj))

			assert.Equal(t, tt.expected, obj)
		})
	}
}
