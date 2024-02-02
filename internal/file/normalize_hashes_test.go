package file

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeHashes(t *testing.T) {

	tests := []struct {
		name  string
		input []crypto.Hash
		want  []crypto.Hash
	}{
		{
			name: "deduplicate hashes",
			input: []crypto.Hash{
				crypto.SHA1,
				crypto.SHA1,
			},
			want: []crypto.Hash{
				crypto.SHA1,
			},
		},
		{
			name: "sort hashes",
			input: []crypto.Hash{
				crypto.SHA512,
				crypto.SHA1,
			},
			want: []crypto.Hash{
				crypto.SHA1,
				crypto.SHA512,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeHashes(tt.input))
		})
	}
}
