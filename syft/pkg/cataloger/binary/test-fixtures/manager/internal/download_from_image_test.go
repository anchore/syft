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
		name        string
		fingerprint string
		expected    bool
	}{
		{
			name:        "no fingerprint",
			fingerprint: "",
			expected:    true,
		},
		{
			name: "fingerprint matches",
			// this is the fingerprint for config in the loop body
			fingerprint: "5177d458eaca031ea16fa707841043df2e31b89be6bae7ea41290aa32f0251a6",
			expected:    false,
		},
		{
			name:        "fingerprint does not match",
			fingerprint: "fingerprint",
			expected:    true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath := filepath.Join(t.TempDir(), "binary")
			fh, err := os.Create(binaryPath + ".fingerprint")
			require.NoError(t, err)

			fh.Write([]byte(tt.fingerprint))
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
