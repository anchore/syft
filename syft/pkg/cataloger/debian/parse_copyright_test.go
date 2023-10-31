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
		{
			fixture: "test-fixtures/copyright/libc6",
			// note: there are other licenses in this file that are not matched --we don't do full text license identification yet
			expected: []string{"GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "test-fixtures/copyright/trilicense",
			expected: []string{"GPL-2", "LGPL-2.1", "MPL-1.1"},
		},
		{
			fixture:  "test-fixtures/copyright/liblzma5",
			expected: []string{"Autoconf", "GPL-2", "GPL-2+", "GPL-3", "LGPL-2", "LGPL-2.1", "LGPL-2.1+", "PD", "PD-debian", "config-h", "noderivs", "permissive-fsf", "permissive-nowarranty", "probably-PD"},
		},
		{
			fixture:  "test-fixtures/copyright/libaudit-common",
			expected: []string{"GPL-1", "GPL-2", "LGPL-2.1"},
		},
		{
			fixture: "test-fixtures/copyright/python",
			// note: this should not capture #, Permission, This, see ... however it's not clear how to fix this (this is probably good enough)
			expected: []string{"#", "Apache", "Apache-2", "Apache-2.0", "Expat", "GPL-2", "ISC", "LGPL-2.1+", "PSF-2", "Permission", "Python", "This", "see"},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			actual := parseLicensesFromCopyright(f)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected package licenses (-want +got):\n%s", diff)
			}
		})
	}
}
