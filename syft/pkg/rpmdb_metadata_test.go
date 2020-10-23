package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/distro"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestRpmMetadata_pURL(t *testing.T) {
	tests := []struct {
		distro   distro.Distro
		metadata RpmdbMetadata
		expected string
	}{
		{
			distro: distro.Distro{
				Type: distro.CentOS,
			},
			metadata: RpmdbMetadata{
				Name:    "p",
				Version: "v",
				Arch:    "a",
				Release: "r",
				Epoch:   1,
			},
			expected: "pkg:rpm/centos/p@1:v-r?arch=a",
		},
		{
			distro: distro.Distro{
				Type: distro.RedHat,
			},
			metadata: RpmdbMetadata{
				Name:    "p",
				Version: "v",
				Arch:    "a",
				Release: "r",
				Epoch:   1,
			},
			expected: "pkg:rpm/redhat/p@1:v-r?arch=a",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := test.metadata.PackageURL(test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
