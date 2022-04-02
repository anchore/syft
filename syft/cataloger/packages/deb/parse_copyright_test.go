package deb

import (
	"os"
	"testing"

	"github.com/go-test/deep"
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
			file, err := os.Open(test.fixture)
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			actual := parseLicensesFromCopyright(file)

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Logf("   %+v", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
			}

			diffs := deep.Equal(actual, test.expected)
			for _, d := range diffs {
				t.Errorf("diff: %+v", d)
			}

		})
	}
}
