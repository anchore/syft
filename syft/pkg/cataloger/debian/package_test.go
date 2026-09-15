package debian

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
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

// Image paths must retain forward slashes on every host.
// Using filepath.Dir breaks these metadata lookups on Windows.
func Test_getAdditionalFileListing_usesPosixImagePaths(t *testing.T) {
	const testDigest = "d41d8cd98f00b204e9800998ecf8427e"

	tests := []struct {
		name              string
		dbPath            string
		contentsByPath    map[string]string
		expectedFiles     []pkg.DpkgFileRecord
		expectedLocations []file.Location
	}{
		{
			name:   "standard status database",
			dbPath: "/var/lib/dpkg/status",
			contentsByPath: map[string]string{
				"/var/lib/dpkg/info/test-package.md5sums":   testDigest + "  usr/bin/test-package\n",
				"/var/lib/dpkg/info/test-package.conffiles": "/etc/test-package.conf\n",
			},
			expectedFiles: []pkg.DpkgFileRecord{
				{
					Path: "/usr/bin/test-package",
					Digest: &file.Digest{
						Algorithm: "md5",
						Value:     testDigest,
					},
				},
				{
					Path:         "/etc/test-package.conf",
					IsConfigFile: true,
				},
			},
			expectedLocations: []file.Location{
				file.NewLocation("/var/lib/dpkg/info/test-package.md5sums").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
				file.NewLocation("/var/lib/dpkg/info/test-package.conffiles").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
			},
		},
		{
			name:   "distroless status database",
			dbPath: "/var/lib/dpkg/status.d/test-package",
			contentsByPath: map[string]string{
				"/var/lib/dpkg/status.d/test-package.md5sums": testDigest + "  usr/bin/test-package\n",
			},
			expectedFiles: []pkg.DpkgFileRecord{
				{
					Path: "/usr/bin/test-package",
					Digest: &file.Digest{
						Algorithm: "md5",
						Value:     testDigest,
					},
				},
			},
			expectedLocations: []file.Location{
				file.NewLocation("/var/lib/dpkg/status.d/test-package.md5sums").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newDpkgMetadataResolver(test.contentsByPath)
			actualFiles, actualLocations := getAdditionalFileListing(
				resolver,
				file.NewLocation(test.dbPath),
				pkg.DpkgDBEntry{Package: "test-package"},
			)

			if diff := cmp.Diff(test.expectedFiles, actualFiles); diff != "" {
				t.Errorf("unexpected package files (-want +got):\n%s", diff)
			}
			require.Equal(t, test.expectedLocations, actualLocations)
		})
	}
}

type dpkgMetadataResolver struct {
	*file.MockResolver
	contentsByPath map[string]string
}

var _ file.Resolver = (*dpkgMetadataResolver)(nil)

func (r *dpkgMetadataResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	contents, exists := r.contentsByPath[location.RealPath]
	if !exists {
		return nil, fmt.Errorf("no contents for path: %s", location.RealPath)
	}

	return io.NopCloser(strings.NewReader(contents)), nil
}

func newDpkgMetadataResolver(contentsByPath map[string]string) *dpkgMetadataResolver {
	paths := make([]string, 0, len(contentsByPath))
	for path := range contentsByPath {
		paths = append(paths, path)
	}

	return &dpkgMetadataResolver{
		MockResolver:   file.NewMockResolverForPaths(paths...),
		contentsByPath: contentsByPath,
	}
}
