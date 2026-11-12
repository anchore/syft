package debian

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func dpkgTestPackage(name, version, arch, dbPath string, evidence ...string) pkg.Package {
	locations := file.NewLocationSet(
		file.NewLocation(dbPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	for _, e := range evidence {
		locations.Add(file.NewLocation(e).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.DebPkg,
		Locations: locations,
		Metadata: pkg.DpkgDBEntry{
			Package:      name,
			Version:      version,
			Architecture: arch,
		},
	}
	p.SetID()
	return p
}

func locationPaths(p pkg.Package) []string {
	var paths []string
	for _, l := range p.Locations.ToSlice() {
		paths = append(paths, l.RealPath)
	}
	sort.Strings(paths)
	return paths
}

// describe renders a package as "name@version (arch): location, location" for comparison.
func describe(p pkg.Package) string {
	return fmt.Sprintf("%s@%s (%s): %s", p.Name, p.Version, p.Metadata.(pkg.DpkgDBEntry).Architecture, strings.Join(locationPaths(p), ", "))
}

func Test_mergeStatusDirDuplicates(t *testing.T) {
	const (
		status    = "/var/lib/dpkg/status"
		statusDir = "/var/lib/dpkg/status.d/"
	)

	tests := []struct {
		name     string
		pkgs     []pkg.Package
		expected []string
	}{
		{
			name: "same package in status and status.d is reported once with both locations",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", statusDir+"gzip"),
				dpkgTestPackage("gzip", "1.13-1", "arm64", status, "/var/lib/dpkg/info/gzip.md5sums"),
			},
			expected: []string{
				"gzip@1.13-1 (arm64): /var/lib/dpkg/info/gzip.md5sums, /var/lib/dpkg/status, /var/lib/dpkg/status.d/gzip",
			},
		},
		{
			name: "order of discovery does not matter",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", status),
				dpkgTestPackage("gzip", "1.13-1", "arm64", statusDir+"gzip"),
			},
			expected: []string{
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status, /var/lib/dpkg/status.d/gzip",
			},
		},
		{
			name: "packages only in status.d are kept (distroless)",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", statusDir+"gzip"),
				dpkgTestPackage("bzip2", "1.0.8-6", "arm64", statusDir+"bzip2"),
			},
			expected: []string{
				"bzip2@1.0.8-6 (arm64): /var/lib/dpkg/status.d/bzip2",
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status.d/gzip",
			},
		},
		{
			name: "packages only in status are kept",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", status),
				dpkgTestPackage("bzip2", "1.0.8-6", "arm64", status),
			},
			expected: []string{
				"bzip2@1.0.8-6 (arm64): /var/lib/dpkg/status",
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status",
			},
		},
		{
			name: "status and status.d describing different packages are all kept",
			pkgs: []pkg.Package{
				dpkgTestPackage("apt", "1.8.2", "amd64", status),
				dpkgTestPackage("dash", "0.5.8-2.4", "amd64", statusDir+"dash"),
				dpkgTestPackage("netbase", "5.4", "all", statusDir+"netbase"),
			},
			expected: []string{
				"apt@1.8.2 (amd64): /var/lib/dpkg/status",
				"dash@0.5.8-2.4 (amd64): /var/lib/dpkg/status.d/dash",
				"netbase@5.4 (all): /var/lib/dpkg/status.d/netbase",
			},
		},
		{
			name: "different versions are not merged",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", status),
				dpkgTestPackage("gzip", "1.12-1", "arm64", statusDir+"gzip"),
			},
			expected: []string{
				"gzip@1.12-1 (arm64): /var/lib/dpkg/status.d/gzip",
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status",
			},
		},
		{
			name: "different architectures are not merged",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", status),
				dpkgTestPackage("gzip", "1.13-1", "amd64", statusDir+"gzip"),
			},
			expected: []string{
				"gzip@1.13-1 (amd64): /var/lib/dpkg/status.d/gzip",
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status",
			},
		},
		{
			name: "different dpkg directories are not merged",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", "/usr/lib/dpkg/status"),
				dpkgTestPackage("gzip", "1.13-1", "arm64", statusDir+"gzip"),
			},
			expected: []string{
				"gzip@1.13-1 (arm64): /usr/lib/dpkg/status",
				"gzip@1.13-1 (arm64): /var/lib/dpkg/status.d/gzip",
			},
		},
		{
			name: "opkg databases are left alone",
			pkgs: []pkg.Package{
				dpkgTestPackage("gzip", "1.13-1", "arm64", "/usr/lib/opkg/status"),
				dpkgTestPackage("gzip", "1.13-1", "arm64", "/usr/lib/opkg/info/gzip.control"),
			},
			expected: []string{
				"gzip@1.13-1 (arm64): /usr/lib/opkg/info/gzip.control",
				"gzip@1.13-1 (arm64): /usr/lib/opkg/status",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputErr := errors.New("passed through")
			inputRels := []artifact.Relationship{{Type: artifact.DependencyOfRelationship}}

			pkgs, rels, err := mergeStatusDirDuplicates(tt.pkgs, inputRels, inputErr)

			assert.Equal(t, inputErr, err)
			assert.Equal(t, inputRels, rels)

			var got []string
			ids := make(map[artifact.ID]struct{})
			for _, p := range pkgs {
				got = append(got, describe(p))
				ids[p.ID()] = struct{}{}
			}
			sort.Strings(got)

			assert.Equal(t, tt.expected, got)
			assert.Len(t, ids, len(pkgs), "every package should have a distinct ID")
		})
	}
}

func Test_mergeStatusDirDuplicates_mergedPackageID(t *testing.T) {
	fromStatus := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status")
	fromStatusDir := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip")
	originalID := fromStatus.ID()

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{fromStatus, fromStatusDir}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)

	// the ID covers locations, so it must be recomputed once the status.d location is added
	expected := got[0]
	expected.SetID()
	assert.Equal(t, expected.ID(), got[0].ID())
	assert.NotEqual(t, originalID, got[0].ID())
}

// the fixture holds verbatim records from a Docker Hardened Images Debian 13 image, which lists every installed
// package in both /var/lib/dpkg/status and /var/lib/dpkg/status.d/<name>. The fixture arranges them so that gzip is
// in both, tzdata is only in status, and bzip2 is only in status.d.
func TestDpkgCataloger_statusAndStatusDir(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/status-and-status-d").
		WithErrorAssertion(require.NoError).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			got := make(map[string][]string)
			for _, p := range pkgs {
				key := p.Name + "@" + p.Version
				require.NotContains(t, got, key, "package reported more than once")
				got[key] = locationPaths(p)
			}

			assert.Equal(t, map[string][]string{
				"gzip@1.13-1+dhi1": {
					"var/lib/dpkg/info/gzip.list",
					"var/lib/dpkg/info/gzip.md5sums",
					"var/lib/dpkg/status",
					"var/lib/dpkg/status.d/gzip",
				},
				"tzdata@2026b-0+deb13u1+dhi2": {"var/lib/dpkg/status"},
				"bzip2@1.0.8-6+dhi2":          {"var/lib/dpkg/status.d/bzip2"},
			}, got)

			for _, p := range pkgs {
				if p.Name != "gzip" {
					continue
				}
				entry, ok := p.Metadata.(pkg.DpkgDBEntry)
				require.True(t, ok)
				assert.NotEmpty(t, entry.Files, "the merged package keeps the file listing found beside the status file")
				assert.Equal(t, []string{"var/lib/dpkg/status"}, evidencePaths(p, pkg.PrimaryEvidenceAnnotation))
				assert.Contains(t, evidencePaths(p, pkg.SupportingEvidenceAnnotation), "var/lib/dpkg/status.d/gzip")
			}
		}).
		TestCataloger(t, NewDBCataloger())
}

// when several layers are cataloged the status file is seen once per layer, as a package per layer that share an ID
// and collapse into one downstream. The merge must keep that true.
func Test_mergeStatusDirDuplicates_statusInSeveralLayers(t *testing.T) {
	statusInLayer := func(layer string) pkg.Package {
		p := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status")
		p.Locations = file.NewLocationSet(
			file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/var/lib/dpkg/status", FileSystemID: layer}).
				WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		p.SetID()
		return p
	}
	lower, upper := statusInLayer("sha256:lower"), statusInLayer("sha256:upper")
	require.Equal(t, lower.ID(), upper.ID(), "the same status entry in two layers shares an ID before merging")

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{
		lower,
		dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip"),
		upper,
	}, nil, nil)
	require.NoError(t, err)

	require.Len(t, got, 2, "one package per layer the status file was seen in")
	assert.Equal(t, got[0].ID(), got[1].ID(), "both must still collapse into one package downstream")
	for _, p := range got {
		assert.Equal(t, []string{"/var/lib/dpkg/status", "/var/lib/dpkg/status.d/gzip"}, locationPaths(p))
	}
}

// evidencePaths returns the location paths of a package carrying the given evidence annotation.
func evidencePaths(p pkg.Package, evidence string) []string {
	var paths []string
	for _, l := range p.Locations.ToSlice() {
		if l.Annotations[pkg.EvidenceAnnotationKey] == evidence {
			paths = append(paths, l.RealPath)
		}
	}
	sort.Strings(paths)
	return paths
}

func Test_mergeStatusDirDuplicates_statusIsPrimaryEvidence(t *testing.T) {
	fromStatusDir := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip", "/usr/share/doc/gzip/copyright")
	fromStatus := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status", "/var/lib/dpkg/info/gzip.md5sums")

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{fromStatusDir, fromStatus}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)

	assert.Equal(t, []string{"/var/lib/dpkg/status"}, evidencePaths(got[0], pkg.PrimaryEvidenceAnnotation))
	assert.Equal(t, []string{
		"/usr/share/doc/gzip/copyright",
		"/var/lib/dpkg/info/gzip.md5sums",
		"/var/lib/dpkg/status.d/gzip",
	}, evidencePaths(got[0], pkg.SupportingEvidenceAnnotation))

	// the package that was folded in is left as it was found
	assert.Equal(t, []string{"/var/lib/dpkg/status.d/gzip"}, evidencePaths(fromStatusDir, pkg.PrimaryEvidenceAnnotation))
}
