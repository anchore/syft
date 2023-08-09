package packagemetadata

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverTypeNames_byExample(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "go case",
			want: "ApkMetadata",
		},
		{
			name: "type shadowed with another type",
			want: "RpmDBMetadata",
		},
		{
			name: "type shadows another type",
			want: "RpmArchiveMetadata",
		},
	}

	got, err := DiscoverTypeNames()
	require.NotEmpty(t, got)
	gotSet := strset.New(got...)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, gotSet.Has(tt.want))
			require.NoError(t, err)
		})
	}
}
