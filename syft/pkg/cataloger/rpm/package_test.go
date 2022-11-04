package rpm

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata pkg.RpmMetadata
		expected string
	}{
		{
			name: "go case",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: pkg.RpmMetadata{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/rhel/p@v-r?distro=rhel-8.4",
		},
		{
			name: "with arch and epoch",
			distro: &linux.Release{
				ID:        "centos",
				VersionID: "7",
			},
			metadata: pkg.RpmMetadata{
				Name:    "p",
				Version: "v",
				Arch:    "a",
				Release: "r",
				Epoch:   intRef(1),
			},
			expected: "pkg:rpm/centos/p@v-r?arch=a&epoch=1&distro=centos-7",
		},
		{
			name: "missing distro",
			metadata: pkg.RpmMetadata{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/p@v-r",
		},
		{
			name: "with upstream source rpm info",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: pkg.RpmMetadata{
				Name:      "p",
				Version:   "v",
				Release:   "r",
				SourceRpm: "sourcerpm",
			},
			expected: "pkg:rpm/rhel/p@v-r?upstream=sourcerpm&distro=rhel-8.4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.metadata, test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
