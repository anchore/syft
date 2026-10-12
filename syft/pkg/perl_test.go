package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCpanDistribution_OwnedFiles(t *testing.T) {
	tests := []struct {
		name     string
		metadata CpanDistribution
		expected []string
	}{
		{
			name: "sorted and deduplicated",
			metadata: CpanDistribution{
				// a distribution that merged more than one packlist can claim the same path twice
				Files: []string{"/lib/URI.pm", "/lib/URI/Escape.pm", "/lib/URI.pm"},
			},
			expected: []string{"/lib/URI.pm", "/lib/URI/Escape.pm"},
		},
		{
			// this is what a NO_PACKLIST install leaves behind: an install.json and nothing else
			name:     "install.json only owns nothing",
			metadata: CpanDistribution{Dist: "URI-5.35", Modules: []CpanModule{{Name: "URI"}}},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.metadata.OwnedFiles())
		})
	}
}

func TestCpanDistribution_isFileOwner(t *testing.T) {
	var owner any = CpanDistribution{}
	_, ok := owner.(FileOwner)
	require.True(t, ok, "the file-ownership relationship workers only see metadata that satisfies FileOwner")

	// the unpacked-release tier has no packlist, so it deliberately does not
	var release any = CpanUnpackedRelease{}
	_, ok = release.(FileOwner)
	assert.False(t, ok)
}
