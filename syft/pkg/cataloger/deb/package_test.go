package deb

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata pkg.DpkgMetadata
		expected string
	}{
		{
			name: "go case",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
				IDLike: []string{
					"debian",
				},
			},
			metadata: pkg.DpkgMetadata{
				Package: "p",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?distro=debian-11",
		},
		{
			name: "missing ID_LIKE",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
			},
			metadata: pkg.DpkgMetadata{
				Package: "p",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?distro=debian-11",
		},
		{
			name: "with arch info",
			distro: &linux.Release{
				ID: "ubuntu",
				IDLike: []string{
					"debian",
				},
				VersionID: "16.04",
			},
			metadata: pkg.DpkgMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:deb/ubuntu/p@v?arch=a&distro=ubuntu-16.04",
		},
		{
			name: "missing distro",
			metadata: pkg.DpkgMetadata{
				Package: "p",
				Version: "v",
			},
			expected: "",
		},
		{
			name: "with upstream qualifier with source pkg name info",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
				IDLike: []string{
					"debian",
				},
			},
			metadata: pkg.DpkgMetadata{
				Package: "p",
				Source:  "s",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?upstream=s&distro=debian-11",
		},
		{
			name: "with upstream qualifier with source pkg name and version info",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
				IDLike: []string{
					"debian",
				},
			},
			metadata: pkg.DpkgMetadata{
				Package:       "p",
				Source:        "s",
				Version:       "v",
				SourceVersion: "2.3",
			},
			expected: "pkg:deb/debian/p@v?upstream=s%402.3&distro=debian-11",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.metadata, test.distro)
			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected packageURL (-want +got):\n%s", diff)
			}
		})
	}
}
