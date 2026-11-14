package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isDistInfoLicenseCandidate(t *testing.T) {
	tests := []struct {
		name       string
		recordPath string
		want       bool
	}{
		{name: "directly in dist-info", recordPath: "x.dist-info/LICENSE", want: true},
		{name: "under licenses", recordPath: "x.dist-info/licenses/LICENSE", want: true},
		{name: "nested under licenses", recordPath: "x.dist-info/licenses/vendor/LICENSE", want: true},
		{name: "other subdirectory of dist-info", recordPath: "x.dist-info/sub/LICENSE", want: false},
		{name: "sibling directory sharing the prefix", recordPath: "x.dist-info2/LICENSE", want: false},
		{name: "outside dist-info", recordPath: "x/LICENSE", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDistInfoLicenseCandidate("x.dist-info", tt.recordPath))
		})
	}
}
