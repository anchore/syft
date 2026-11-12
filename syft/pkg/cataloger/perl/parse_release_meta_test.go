package perl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isBuildLeftover(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/root/.cpanm/work/1785183030.2/Clone-0.50/META.json", want: true},
		{path: "/root/.cpan/build/Encode-3.24-0/META.json", want: true},
		// a directory scan reports paths relative to its root
		{path: "root/.cpanm/work/1785183030.2/Clone-0.50/META.yml", want: true},
		{path: "/home/app/.cpan/build/Text-CSV-2.06-mQ3Ktb/META.json", want: true},
		// a release deliberately unpacked somewhere else is still reported
		{path: "/opt/vendor/Text-CSV-2.06/META.json", want: false},
		{path: "/src/Encode-3.24/META.json", want: false},
		// the client's own directories are not build trees; only work/ and build/ under them are
		{path: "/root/.cpanm/latest-build/META.json", want: false},
		{path: "/root/.cpan/sources/META.json", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isBuildLeftover(tt.path))
		})
	}
}
