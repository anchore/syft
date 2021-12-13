package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"

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
				Epoch:   intRef(1),
			},
			expected: "pkg:rpm/centos/p@v-r?arch=a&epoch=1",
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
				Epoch:   nil,
			},
			expected: "pkg:rpm/redhat/p@v-r?arch=a",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := test.metadata.PackageURL(&test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestRpmMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata RpmdbMetadata
		expected []string
	}{
		{
			metadata: RpmdbMetadata{
				Files: []RpmdbFileRecord{
					{Path: "/somewhere"},
					{Path: "/else"},
				},
			},
			expected: []string{
				"/else",
				"/somewhere",
			},
		},
		{
			metadata: RpmdbMetadata{
				Files: []RpmdbFileRecord{
					{Path: "/somewhere"},
					{Path: ""},
				},
			},
			expected: []string{
				"/somewhere",
			},
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.expected, ","), func(t *testing.T) {
			var i interface{} = test.metadata
			actual := i.(FileOwner).OwnedFiles()
			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func intRef(i int) *int {
	return &i
}
