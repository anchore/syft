package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func TestIsDownloadStale(t *testing.T) {

	cases := []struct {
		name     string
		digest   string
		expected bool
	}{
		{
			name:     "no digest",
			digest:   "",
			expected: true,
		},
		{
			name: "digest matches",
			// this is the digest for config in the loop body
			digest:   "c9c8007f9c55c2f1",
			expected: false,
		},
		{
			name:     "digest does not match",
			digest:   "bogus",
			expected: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := filepath.Join(t.TempDir(), "binary")
			fh, err := os.Create(binaryPath + digestFileSuffix)
			require.NoError(t, err)

			fh.Write([]byte(tt.digest))
			require.NoError(t, fh.Close())

			cfg := config.BinaryFromImage{
				GenericName: "name",
				Version:     "version",
				Images: []config.Image{{
					Reference: "ref",
					Platform:  "platform",
				}},
				PathsInImage: []string{"path"},
			}

			assert.Equal(t, tt.expected, isDownloadStale(cfg, []string{binaryPath}))
		})
	}

}
