package debian

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
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
		{
			// machine-readable file with both License: short-name fields and
			// embedded license-text URLs; URL-detection is additive on top of
			// the existing License: field captures.
			fixture:  "testdata/copyright/format-header",
			expected: []string{"Apache-2.0", "MIT"},
		},
		{
			// no License: short-name fields anywhere, but a clear seeAlso URL
			// for MIT — exercises URL-only detection.
			fixture:  "testdata/copyright/url-only-license",
			expected: []string{"MIT"},
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

func TestHasMachineReadableFormat(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "deb822 spec URL is the canonical Format header",
			content: `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: foo

Files: *
License: MIT
`,
			want: true,
		},
		{
			name: "http (not https) Format URL is also accepted",
			content: `Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: foo
`,
			want: true,
		},
		{
			name: "Format header may sit below other first-stanza fields",
			content: `Upstream-Name: foo
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Source: https://example.com/foo
`,
			want: true,
		},
		{
			name:    "Format-less narrative copyright is not machine-readable",
			content: "This package was put together by Example.\n\nIt was downloaded from https://example.com/foo.\n",
			want:    false,
		},
		{
			name: "Format appearing only after the first stanza must not count",
			content: `Upstream-Name: foo

Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
`,
			want: false,
		},
		{
			name:    "empty file",
			content: "",
			want:    false,
		},
		{
			name:    "Format without scheme does not match — the spec requires an http(s) URL",
			content: "Format: copyright-format/1.0\n",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasMachineReadableFormat(tt.content))
		})
	}
}

func TestLicenseIDsFromURLs(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "Apache 2.0 seeAlso URL",
			line: "See http://www.apache.org/licenses/LICENSE-2.0 for details.",
			want: []string{"Apache-2.0"},
		},
		{
			name: "MIT seeAlso URL with https",
			line: "https://opensource.org/licenses/MIT",
			want: []string{"MIT"},
		},
		{
			name: "trailing punctuation is stripped before lookup",
			line: "(see http://www.apache.org/licenses/LICENSE-2.0.)",
			want: []string{"Apache-2.0"},
		},
		{
			name: "non-license URL does not produce a finding",
			line: "Source: https://example.com/foo",
			want: nil,
		},
		{
			name: "no URL on the line",
			line: "License: GPL-2",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, licenseIDsFromURLs(tt.line))
		})
	}
}
