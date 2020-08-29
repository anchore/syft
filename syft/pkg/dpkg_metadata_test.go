package pkg

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
)

func TestDpkgMetadata_pURL(t *testing.T) {
	tests := []struct {
		distro   distro.Distro
		metadata DpkgMetadata
		expected string
	}{
		{
			distro: distro.Distro{
				Type: distro.Debian,
			},
			metadata: DpkgMetadata{
				Package:      "p",
				Source:       "s",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:deb/debian/p@v?arch=a",
		},
		{
			distro: distro.Distro{
				Type: distro.Ubuntu,
			},
			metadata: DpkgMetadata{
				Package:      "p",
				Source:       "s",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:deb/ubuntu/p@v?arch=a",
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
