package perl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name    string
		dist    string
		version string
		author  string
		want    string
	}{
		{
			name:    "author available",
			dist:    "URI",
			version: "5.35",
			author:  "OALDERS",
			want:    "pkg:cpan/URI@5.35?author=OALDERS",
		},
		{
			name:    "no author known, e.g. a packlist-derived package",
			dist:    "Text-CSV",
			version: "2.06",
			want:    "pkg:cpan/Text-CSV@2.06",
		},
		{
			name:    "case is preserved",
			dist:    "JSON-MaybeXS",
			version: "1.004008",
			author:  "ETHER",
			want:    "pkg:cpan/JSON-MaybeXS@1.004008?author=ETHER",
		},
		{
			name:    "v-prefixed version is preserved",
			dist:    "CPAN-02Packages-Search",
			version: "v1.0.0",
			author:  "SKAJI",
			want:    "pkg:cpan/CPAN-02Packages-Search@v1.0.0?author=SKAJI",
		},
		{
			name: "no version",
			dist: "IO-Socket-SSL",
			want: "pkg:cpan/IO-Socket-SSL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.dist, tt.version, tt.author))
		})
	}
}

func Test_authorFromPathname(t *testing.T) {
	tests := []struct {
		pathname string
		want     string
	}{
		{pathname: "O/OA/OALDERS/URI-5.35.tar.gz", want: "OALDERS"},
		{pathname: "S/SK/SKAJI/CPAN-02Packages-Search-v1.0.0.tar.gz", want: "SKAJI"},
		// not enough segments to name an author: better to omit than to guess
		{pathname: "OALDERS/URI-5.35.tar.gz", want: ""},
		{pathname: "URI-5.35.tar.gz", want: ""},
		{pathname: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.pathname, func(t *testing.T) {
			assert.Equal(t, tt.want, authorFromPathname(tt.pathname))
		})
	}
}
