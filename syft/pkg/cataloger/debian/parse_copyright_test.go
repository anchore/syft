package debian

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestParseLicensesFromCopyright(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []string
	}{
		// Non-machine-readable files (no Format: header):
		// Only common-licenses paths are extracted; full text goes to classifier fallback.
		{
			fixture:  "testdata/copyright/libc6",
			expected: []string{"GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "testdata/copyright/trilicense",
			expected: []string{"GPL-2", "LGPL-2.1", "MPL-1.1"},
		},
		{
			fixture:  "testdata/copyright/python",
			expected: nil,
		},
		{
			fixture:  "testdata/copyright/cuda",
			expected: nil,
		},
		{
			fixture:  "testdata/copyright/dev-kit",
			expected: nil,
		},
		{
			fixture:  "testdata/copyright/microsoft",
			expected: nil,
		},
		// Machine-readable files (with Format: header):
		// Full machine-readable parsing including multi-line license headings.
		{
			fixture:  "testdata/copyright/liblzma5",
			expected: []string{"Autoconf", "GPL-2", "GPL-2+", "GPL-3", "LGPL-2", "LGPL-2.1", "LGPL-2.1+", "PD", "PD-debian", "config-h", "noderivs", "permissive-fsf", "permissive-nowarranty", "probably-PD"},
		},
		{
			fixture:  "testdata/copyright/libaudit-common",
			expected: []string{"GPL-1", "GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "testdata/copyright/non-machine-readable",
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			actual := parseLicensesFromCopyright(f)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected package licenses (-want +got):
%s", diff)
			}
		})
	}
}
