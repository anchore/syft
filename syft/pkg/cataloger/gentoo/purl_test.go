package gentoo

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			"app-admin/eselect",
			"1.4.15",
			"pkg:ebuild/app-admin/eselect@1.4.15",
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s@%s", tt.name, tt.version), func(t *testing.T) {
			assert.Equal(t, tt.want, packageURL(tt.name, tt.version))
		})
	}
}
