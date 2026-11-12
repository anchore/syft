package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func TestCandidateVendorsForRPM(t *testing.T) {
	tests := []struct {
		name     string
		metadata any
		expected []string
	}{
		{
			name: "database vendor with publisher URL",
			metadata: pkg.RpmDBEntry{
				Vendor: "SUSE LLC <https://www.suse.com/>",
			},
			expected: []string{"susellc"},
		},
		{
			name: "archive vendor with publisher URL",
			metadata: pkg.RpmArchive{
				Vendor: "SUSE LLC <https://www.suse.com/>",
			},
			expected: []string{"susellc"},
		},
		{
			name: "plain vendor",
			metadata: pkg.RpmDBEntry{
				Vendor: "Red Hat, Inc.",
			},
			expected: []string{"redhat"},
		},
		{
			name: "non-URL angle-bracket suffix",
			metadata: pkg.RpmDBEntry{
				Vendor: "Example <support@example.com>",
			},
			expected: []string{"example<support@example.com>"},
		},
		{
			name: "non-HTTP URL",
			metadata: pkg.RpmDBEntry{
				Vendor: "Example <ftp://example.com>",
			},
			expected: []string{"example<ftp://example.com>"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := pkg.Package{Metadata: test.metadata}
			assert.ElementsMatch(t, test.expected, candidateVendorsForRPM(p).uniqueValues())
		})
	}
}
