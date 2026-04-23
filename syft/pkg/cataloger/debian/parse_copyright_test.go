package debian

import (
	"os"
	"strings"
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
			// no Format header; not machine-readable, returns nil
			fixture:  "testdata/copyright/libc6",
			expected: nil,
		},
		{
			// no Format header; not machine-readable, returns nil
			fixture:  "testdata/copyright/trilicense",
			expected: nil,
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
			// no Format header; not machine-readable, returns nil
			// previously this captured nonsensical values like "#", "Permission", "This", "see"
			fixture:  "testdata/copyright/python",
			expected: nil,
		},
		{
			// no Format header; not machine-readable, returns nil
			fixture:  "testdata/copyright/cuda",
			expected: nil,
		},
		{
			// no Format header; not machine-readable, returns nil
			fixture:  "testdata/copyright/dev-kit",
			expected: nil,
		},
		{
			// no Format header; not machine-readable, returns nil
			fixture:  "testdata/copyright/microsoft",
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
				t.Errorf("unexpected package licenses (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHasFormatHeader(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "valid http Format header",
			content:  "Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n",
			expected: true,
		},
		{
			name:     "valid https Format header",
			content:  "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n",
			expected: true,
		},
		{
			name:     "blank lines before Format header",
			content:  "\n\nFormat: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n",
			expected: true,
		},
		{
			name:     "no Format header",
			content:  "This is the Debian prepackaged version of foo.\n",
			expected: false,
		},
		{
			name:     "Format header is not first non-blank line",
			content:  "Some-Field: value\nFormat: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n",
			expected: false,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
		{
			name:     "only blank lines",
			content:  "\n\n\n",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := hasFormatHeader(test.content)
			if actual != test.expected {
				t.Errorf("hasFormatHeader(%q) = %v, want %v", test.content, actual, test.expected)
			}
		})
	}
}

func TestParseLicensesFromCopyrightInline(t *testing.T) {
	// verify that a file with License: fields but no Format header returns nil
	content := `License: GPL-2
License: LGPL-2.1
`
	actual := parseLicensesFromCopyright(strings.NewReader(content))
	if actual != nil {
		t.Errorf("expected nil for non-machine-readable file, got %v", actual)
	}
}
