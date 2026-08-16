package debian

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata pkg.DpkgDBEntry
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
			metadata: pkg.DpkgDBEntry{
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
			metadata: pkg.DpkgDBEntry{
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
			metadata: pkg.DpkgDBEntry{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:deb/ubuntu/p@v?arch=a&distro=ubuntu-16.04",
		},
		{
			name: "missing distro",
			metadata: pkg.DpkgDBEntry{
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
			metadata: pkg.DpkgDBEntry{
				Package: "p",
				Source:  "s",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?distro=debian-11&upstream=s",
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
			metadata: pkg.DpkgDBEntry{
				Package:       "p",
				Source:        "s",
				Version:       "v",
				SourceVersion: "2.3",
			},
			expected: "pkg:deb/debian/p@v?distro=debian-11&upstream=s%402.3",
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

func Test_extractDeclaredLicenses(t *testing.T) {
	ctx := context.Background()
	dbLocation := file.NewLocation("/var/lib/opkg/status")

	tests := []struct {
		name     string
		raw      string
		expected []string
	}{
		{
			name:     "empty input returns nil",
			raw:      "",
			expected: nil,
		},
		{
			name:     "single SPDX identifier kept whole",
			raw:      "MIT",
			expected: []string{"MIT"},
		},
		{
			name:     "valid SPDX expression kept whole",
			raw:      "Apache-2.0 OR MIT",
			expected: []string{"Apache-2.0 OR MIT"},
		},
		{
			name:     "non-expression space-separated list is split",
			raw:      "GPL-2.0 BSD-3-Clause",
			expected: []string{"GPL-2.0", "BSD-3-Clause"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractDeclaredLicenses(ctx, test.raw, dbLocation)
			var gotValues []string
			for _, l := range got {
				gotValues = append(gotValues, l.Value)
			}
			// NewLicensesFromLocationWithContext does not guarantee output order
			sort.Strings(gotValues)
			want := append([]string(nil), test.expected...)
			sort.Strings(want)
			if diff := cmp.Diff(want, gotValues); diff != "" {
				t.Errorf("unexpected licenses (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_newDpkgPackage_declaredLicense(t *testing.T) {
	// the License field is not persisted on pkg.DpkgDBEntry, so this guards that the inline opkg/ipkg license
	// declared on the raw metadata still flows into the built package's license set
	tests := []struct {
		name     string
		metadata dpkgExtractedMetadata
		expected []string
	}{
		{
			name:     "no declared license",
			metadata: dpkgExtractedMetadata{Package: "apt", Version: "1.8.2"},
			expected: nil,
		},
		{
			name:     "inline license flows to package",
			metadata: dpkgExtractedMetadata{Package: "dropbear", Version: "2024.85-r0", License: "MIT"},
			expected: []string{"MIT"},
		},
		{
			name:     "space-separated licenses split into the set",
			metadata: dpkgExtractedMetadata{Package: "busybox", Version: "1.36.1", License: "GPL-2.0 BSD-3-Clause"},
			expected: []string{"BSD-3-Clause", "GPL-2.0"},
		},
		{
			name:     "valid SPDX expression kept whole",
			metadata: dpkgExtractedMetadata{Package: "curl", Version: "8.5.0", License: "Apache-2.0 OR MIT"},
			expected: []string{"Apache-2.0 OR MIT"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := newDpkgPackage(context.Background(), test.metadata, file.NewLocation("/var/lib/opkg/status"), nil, nil)

			var got []string
			for _, l := range p.Licenses.ToSlice() {
				got = append(got, l.Value)
			}
			// the license set does not guarantee output order
			sort.Strings(got)
			require.Equal(t, test.expected, got)
		})
	}
}
