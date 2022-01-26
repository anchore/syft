package linux

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFromPURLDistro(t *testing.T) {
	tests := []struct {
		purl    string
		release *Release
	}{
		{
			purl: "pkg:apk/alpine/asdf?distro=alpine-1.23",
			release: &Release{
				Name:      "alpine",
				VersionID: "1.23",
			},
		},
		{
			purl: "pkg:apk/alpine/asdf?distro=debian-11.4",
			release: &Release{
				Name:      "debian",
				VersionID: "11.4",
			},
		},
		{
			purl: "pkg:apk/alpine/asdf",
		},
	}

	for _, test := range tests {
		t.Run(test.purl, func(t *testing.T) {
			r := NewFromPURLDistro(test.purl)

			if test.release != nil {
				assert.NotNil(t, r)
				assert.Equal(t, test.release.Name, r.ID)
				assert.Equal(t, test.release.Name, r.Name)
				assert.Equal(t, test.release.VersionID, r.VersionID)
			} else {
				assert.Nil(t, r)
			}
		})
	}
}
