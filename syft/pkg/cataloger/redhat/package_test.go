package redhat

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
		metadata pkg.RpmDBEntry
		expected string
	}{
		{
			name: "go case",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Release: "r",
				Epoch:   nil,
			},
			expected: "pkg:rpm/redhat/p@v-r?distro=rhel-8.4",
		},
		{
			name: "with arch and epoch",
			distro: &linux.Release{
				ID:        "centos",
				VersionID: "7",
			},
			metadata: pkg.RpmDBEntry{
				Name:    "p",
				Version: "v",
				Arch:    "a",
				Release: "r",
				Epoch:   intRef(1),
			},
			expected: "pkg:rpm/centos/p@v-r?arch=a&distro=centos-7&epoch=1",
		},
		{
			name: "missing distro",
			metadata: pkg.RpmDBEntry{
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
			metadata: pkg.RpmDBEntry{
				Name:      "p",
				Version:   "v",
				Release:   "r",
				SourceRpm: "sourcerpm",
			},
			expected: "pkg:rpm/redhat/p@v-r?distro=rhel-8.4&upstream=sourcerpm",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(
				test.metadata.Name,
				test.metadata.Arch,
				test.metadata.Epoch,
				test.metadata.SourceRpm,
				test.metadata.Version,
				test.metadata.Release,
				test.distro,
			)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
