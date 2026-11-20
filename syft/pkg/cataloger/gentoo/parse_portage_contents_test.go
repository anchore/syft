package gentoo

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestParseContentsObjectLine(t *testing.T) {
	digest := func(value string) *file.Digest {
		return &file.Digest{Algorithm: "md5", Value: value}
	}

	tests := []struct {
		name     string
		line     string
		expected pkg.PortageFileRecord
		wantOK   bool
	}{
		{
			name:     "plain path",
			line:     "obj /usr/bin/skopeo 376c02bd3b22804df8fdfdc895e7dbfb 1649284374",
			expected: pkg.PortageFileRecord{Path: "/usr/bin/skopeo", Digest: digest("376c02bd3b22804df8fdfdc895e7dbfb")},
			wantOK:   true,
		},
		{
			name:     "path with a space",
			line:     "obj /usr/share/fonts/My Font.ttf d41d8cd98f00b204e9800998ecf8427e 1649284375",
			expected: pkg.PortageFileRecord{Path: "/usr/share/fonts/My Font.ttf", Digest: digest("d41d8cd98f00b204e9800998ecf8427e")},
			wantOK:   true,
		},
		{
			name:     "path with several spaces",
			line:     "obj /opt/A B/c d/e f.so c01eb6950f03419e09d4fc88cb42ff6f 1649284375",
			expected: pkg.PortageFileRecord{Path: "/opt/A B/c d/e f.so", Digest: digest("c01eb6950f03419e09d4fc88cb42ff6f")},
			wantOK:   true,
		},
		{
			name:   "directory entry",
			line:   "dir /usr/bin",
			wantOK: false,
		},
		{
			name:   "symlink entry",
			line:   "sym /usr/lib/libfoo.so -> libfoo.so.1 1649284375",
			wantOK: false,
		},
		{
			name:   "truncated object entry",
			line:   "obj /usr/bin/skopeo",
			wantOK: false,
		},
		{
			name:   "empty line",
			line:   "",
			wantOK: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, ok := parseContentsObjectLine(test.line)
			assert.Equal(t, test.wantOK, ok)
			if test.wantOK {
				assert.Equal(t, test.expected, record)
			}
		})
	}
}
