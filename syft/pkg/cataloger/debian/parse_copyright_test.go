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
			fixture: "testdata/copyright/libc6",
			// note: there are other licenses in this file that are not matched --we don't do full text license identification yet
			// NOTE: This test file is NOT machine-readable format, but we test the parser behavior
			// when files are forced through the machine-readable parser
			expected: []string{"GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "testdata/copyright/trilicense",
			expected: []string{"GPL-2", "LGPL-2.1", "MPL-1.1"},
		},
		{
			fixture:  "testdata/copyright/liblzma5",
			expected: []string{"Autoconf", "GPL-2", "GPL-2+", "GPL-3", "LGPL-2", "LGPL-2.1", "LGPL-2.1+", "PD", "PD-debian", "config-h", "noderivs", "permissive-fsf", "permissive-nowarranty", "probably-PD"},
		},
		{
			fixture:  "testdata/copyright/libaudit-common",
			expected: []string{"GPL-1", "GPL-2", "LGPL-2.1"},
		},
		{
			fixture: "testdata/copyright/python",
			// note: this should not capture #, Permission, This, see ... however it's not clear how to fix this (this is probably good enough)
			expected: []string{"#", "Apache", "Apache-2", "Apache-2.0", "Expat", "GPL-2", "ISC", "LGPL-2.1+", "PSF-2", "Permission", "Python", "This", "see"},
		},
		{
			fixture:  "testdata/copyright/cuda",
			expected: []string{"NVIDIA Software License Agreement and CUDA Supplement to Software License Agreement"},
		},
		{
			fixture:  "testdata/copyright/dev-kit",
			expected: []string{"LICENSE AGREEMENT FOR NVIDIA SOFTWARE DEVELOPMENT KITS"},
		},
		{
			fixture:  "testdata/copyright/microsoft",
			expected: []string{"LICENSE AGREEMENT FOR MICROSOFT PRODUCTS"},
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

func TestIsMachineReadableFormat(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected bool
	}{
		{
			name:     "machine readable format with https URL",
			fixture:  "testdata/copyright/machine_readable",
			expected: true,
		},
		{
			name:     "non machine readable format (no Format field)",
			fixture:  "testdata/copyright/non_machine_readable",
			expected: false,
		},
		{
			name:     "libc6 is not machine readable",
			fixture:  "testdata/copyright/libc6",
			expected: false,
		},
		{
			name:     "python copyright is not machine readable",
			fixture:  "testdata/copyright/python",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(test.fixture)
			require.NoError(t, err)

			actual := IsMachineReadableFormat(data)
			if actual != test.expected {
				t.Errorf("IsMachineReadableFormat() = %v, want %v", actual, test.expected)
			}
		})
	}
}
