package debian

import (
	"context"
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

// dpkgTestPackageAt is dpkgTestPackage with full control over the database location.
func dpkgTestPackageAt(name, version, arch string, dbLocation file.Location) pkg.Package {
	p := dpkgTestPackage(name, version, arch, dbLocation.RealPath)
	p.Locations = file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
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
			// covers packages only in status (ordinary Debian) and only in status.d (distroless)
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
			// opkg shares this cataloger and metadata type, and describes each package in both its status file and
			// an info/<name>.control file. Those are not a status.d directory, so they are out of scope here.
			name: "an opkg status entry and its info control file are not merged",
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
			// relationships that do not involve a merged package are kept as they are
			inputRels := []artifact.Relationship{{
				From: file.Coordinates{RealPath: "/a"},
				To:   file.Coordinates{RealPath: "/b"},
				Type: artifact.ContainsRelationship,
			}}

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

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{fromStatus, fromStatusDir}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)

	// the ID covers locations, so it matches neither input...
	assert.NotEqual(t, fromStatus.ID(), got[0].ID())
	assert.NotEqual(t, fromStatusDir.ID(), got[0].ID())

	// ...but the ID of a package found with both locations to begin with
	expected := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status", "/var/lib/dpkg/status.d/gzip")
	assert.Equal(t, expected.ID(), got[0].ID())
}

func Test_mergeStatusDirDuplicates_inputsAreNotModified(t *testing.T) {
	fromStatus := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status")
	fromStatusDir := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip", "/usr/share/doc/gzip/copyright")

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{fromStatusDir, fromStatus}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)

	// annotations are a map, so a change to the merged package must not reach the packages it was built from
	for _, l := range got[0].Locations.ToSlice() {
		l.Annotations["changed"] = "true"
	}

	assert.Equal(t, []string{"/var/lib/dpkg/status"}, locationPaths(fromStatus))
	assert.Equal(t, []string{"/var/lib/dpkg/status.d/gzip"}, evidencePaths(fromStatusDir, pkg.PrimaryEvidenceAnnotation))
	for _, input := range []pkg.Package{fromStatus, fromStatusDir} {
		for _, l := range input.Locations.ToSlice() {
			assert.NotContains(t, l.Annotations, "changed", l.RealPath)
		}
	}
}

// the status file is the primary evidence of a merged package and the status.d file supporting evidence. The one
// exception is a scan that tracks which files are hidden by later layers: it drops packages that have no visible
// primary evidence, so a visible status.d file stays primary when the status entry is hidden.
func Test_mergeStatusDirDuplicates_evidence(t *testing.T) {
	withVisibility := func(p pkg.Package, visibility string) pkg.Package {
		locations := file.NewLocationSet()
		for _, l := range p.Locations.ToSlice() {
			locations.Add(l.WithAnnotation(file.VisibleAnnotationKey, visibility))
		}
		p.Locations = locations
		p.SetID()
		return p
	}

	tests := []struct {
		name                string
		statusVisibility    string
		statusDirVisibility string
		expectedPrimary     []string
		expectedSupporting  []string
	}{
		{
			name:               "visibility is not tracked",
			expectedPrimary:    []string{"/var/lib/dpkg/status"},
			expectedSupporting: []string{"/var/lib/dpkg/info/gzip.md5sums", "/var/lib/dpkg/status.d/gzip"},
		},
		{
			name:                "visible status entry",
			statusVisibility:    file.VisibleAnnotation,
			statusDirVisibility: file.VisibleAnnotation,
			expectedPrimary:     []string{"/var/lib/dpkg/status"},
			expectedSupporting:  []string{"/var/lib/dpkg/info/gzip.md5sums", "/var/lib/dpkg/status.d/gzip"},
		},
		{
			name:                "hidden status entry",
			statusVisibility:    file.HiddenAnnotation,
			statusDirVisibility: file.VisibleAnnotation,
			expectedPrimary:     []string{"/var/lib/dpkg/status", "/var/lib/dpkg/status.d/gzip"},
			expectedSupporting:  []string{"/var/lib/dpkg/info/gzip.md5sums"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := mergeStatusDirDuplicates([]pkg.Package{
				withVisibility(dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip"), tt.statusDirVisibility),
				withVisibility(dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status", "/var/lib/dpkg/info/gzip.md5sums"), tt.statusVisibility),
			}, nil, nil)
			require.NoError(t, err)
			require.Len(t, got, 1)

			assert.Equal(t, tt.expectedPrimary, evidencePaths(got[0], pkg.PrimaryEvidenceAnnotation))
			assert.Equal(t, tt.expectedSupporting, evidencePaths(got[0], pkg.SupportingEvidenceAnnotation))

			if tt.statusDirVisibility == "" {
				return
			}
			var visiblePrimary bool
			for _, l := range got[0].Locations.ToSlice() {
				if l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation && isVisible(l) {
					visiblePrimary = true
				}
			}
			assert.True(t, visiblePrimary, "the merged package needs visible primary evidence to be kept")
		})
	}
}

func Test_mergeStatusDirDuplicates_fileListing(t *testing.T) {
	record := func(p string) pkg.DpkgFileRecord {
		return pkg.DpkgFileRecord{Path: p, Digest: &file.Digest{Algorithm: "md5", Value: "d41d8cd98f00b204e9800998ecf8427e"}}
	}
	withFiles := func(p pkg.Package, files ...pkg.DpkgFileRecord) pkg.Package {
		entry := p.Metadata.(pkg.DpkgDBEntry)
		entry.Files = files
		p.Metadata = entry
		p.SetID()
		return p
	}

	tests := []struct {
		name          string
		statusFiles   []pkg.DpkgFileRecord
		statusDFiles  []pkg.DpkgFileRecord
		expectedPaths []string
	}{
		{
			name:          "listing only beside the status.d file is kept",
			statusDFiles:  []pkg.DpkgFileRecord{record("/usr/bin/gzip"), record("/usr/bin/gunzip")},
			expectedPaths: []string{"/usr/bin/gunzip", "/usr/bin/gzip"},
		},
		{
			name:          "listing only beside the status file is kept",
			statusFiles:   []pkg.DpkgFileRecord{record("/usr/bin/gzip")},
			expectedPaths: []string{"/usr/bin/gzip"},
		},
		{
			name:          "listings are combined without repeating a path",
			statusFiles:   []pkg.DpkgFileRecord{record("/usr/bin/gzip"), record("/usr/bin/zcat")},
			statusDFiles:  []pkg.DpkgFileRecord{record("/usr/bin/gunzip"), record("/usr/bin/gzip")},
			expectedPaths: []string{"/usr/bin/gunzip", "/usr/bin/gzip", "/usr/bin/zcat"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := mergeStatusDirDuplicates([]pkg.Package{
				withFiles(dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip"), tt.statusDFiles...),
				withFiles(dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status"), tt.statusFiles...),
			}, nil, nil)
			require.NoError(t, err)
			require.Len(t, got, 1)

			var paths []string
			for _, f := range got[0].Metadata.(pkg.DpkgDBEntry).Files {
				paths = append(paths, f.Path)
			}
			assert.Equal(t, tt.expectedPaths, paths)
		})
	}
}

func Test_mergeStatusDirDuplicates_licenses(t *testing.T) {
	ctx := context.TODO()
	fromStatus := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status")
	fromStatus.Licenses = pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "GPL-3.0-or-later"))
	fromStatus.SetID()
	fromStatusDir := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip")
	fromStatusDir.Licenses = pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "FSFAP"))
	fromStatusDir.SetID()

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{fromStatus, fromStatusDir}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)

	var values []string
	for _, l := range got[0].Licenses.ToSlice() {
		values = append(values, l.Value)
	}
	sort.Strings(values)
	assert.Equal(t, []string{"FSFAP", "GPL-3.0-or-later"}, values)
}

// a dpkg database within an archive has the archive as its real path, so the path within the archive is what
// identifies the database directory.
func Test_mergeStatusDirDuplicates_withinArchive(t *testing.T) {
	nested := func(archive, entry string) file.Location {
		return file.NewLocationFromCoordinates(file.Coordinates{
			RealPath: archive,
			FullPath: archive + file.ArchivePathSeparator + entry,
		})
	}
	fullPaths := func(p pkg.Package) []string {
		var paths []string
		for _, l := range p.Locations.ToSlice() {
			paths = append(paths, l.FullNestedPath())
		}
		sort.Strings(paths)
		return paths
	}

	t.Run("same archive", func(t *testing.T) {
		got, _, err := mergeStatusDirDuplicates([]pkg.Package{
			dpkgTestPackageAt("gzip", "1.13-1", "arm64", nested("/rootfs.tar", "var/lib/dpkg/status")),
			dpkgTestPackageAt("gzip", "1.13-1", "arm64", nested("/rootfs.tar", "var/lib/dpkg/status.d/gzip")),
		}, nil, nil)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{
			"/rootfs.tar!/var/lib/dpkg/status",
			"/rootfs.tar!/var/lib/dpkg/status.d/gzip",
		}, fullPaths(got[0]))
	})

	t.Run("different archives", func(t *testing.T) {
		got, _, err := mergeStatusDirDuplicates([]pkg.Package{
			dpkgTestPackageAt("gzip", "1.13-1", "arm64", nested("/one.tar", "var/lib/dpkg/status")),
			dpkgTestPackageAt("gzip", "1.13-1", "arm64", nested("/two.tar", "var/lib/dpkg/status.d/gzip")),
		}, nil, nil)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})

	t.Run("archive and the filesystem around it", func(t *testing.T) {
		got, _, err := mergeStatusDirDuplicates([]pkg.Package{
			dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status"),
			dpkgTestPackageAt("gzip", "1.13-1", "arm64", nested("/rootfs.tar", "var/lib/dpkg/status.d/gzip")),
		}, nil, nil)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}

// when several layers are cataloged the status file is seen once per layer, as a package per layer that share an ID
// and collapse into one downstream. The merge must keep that true.
func Test_mergeStatusDirDuplicates_statusInSeveralLayers(t *testing.T) {
	statusInLayer := func(layer string) pkg.Package {
		return dpkgTestPackageAt("gzip", "1.13-1", "arm64",
			file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/var/lib/dpkg/status", FileSystemID: layer}))
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

// the fixture holds verbatim records from a Docker Hardened Images Debian 13 image, which lists every installed
// package in both /var/lib/dpkg/status and /var/lib/dpkg/status.d/<name>. The fixture arranges them so that gzip is
// in both, libc6 (which gzip depends on) is only in status, and bzip2 is only in status.d.
func TestDpkgCataloger_statusAndStatusDir(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/status-and-status-d").
		WithErrorAssertion(require.NoError).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			got := make(map[string][]string)
			byName := make(map[string]pkg.Package)
			for _, p := range pkgs {
				key := p.Name + "@" + p.Version
				require.NotContains(t, got, key, "package reported more than once")
				got[key] = locationPaths(p)
				byName[p.Name] = p
			}

			assert.Equal(t, map[string][]string{
				"gzip@1.13-1+dhi1": {
					"var/lib/dpkg/info/gzip.md5sums",
					"var/lib/dpkg/status",
					"var/lib/dpkg/status.d/gzip",
				},
				"libc6@2.41-12+deb13u3+dhi1": {"var/lib/dpkg/status"},
				"bzip2@1.0.8-6+dhi2":         {"var/lib/dpkg/status.d/bzip2"},
			}, got)

			gzip := byName["gzip"]
			entry, ok := gzip.Metadata.(pkg.DpkgDBEntry)
			require.True(t, ok)
			assert.NotEmpty(t, entry.Files, "the merged package keeps the file listing found beside the status file")
			assert.Equal(t, []string{"var/lib/dpkg/status"}, evidencePaths(gzip, pkg.PrimaryEvidenceAnnotation))
			assert.Contains(t, evidencePaths(gzip, pkg.SupportingEvidenceAnnotation), "var/lib/dpkg/status.d/gzip")

			// dependencies are resolved after the merge, so the dependency of gzip on libc6 is reported once and
			// points at the merged package
			var dependencies []string
			for _, r := range relationships {
				if r.Type != artifact.DependencyOfRelationship {
					continue
				}
				from, to := r.From.(pkg.Package), r.To.(pkg.Package)
				dependencies = append(dependencies, from.Name+" -> "+to.Name)
				if to.Name == "gzip" {
					assert.Equal(t, gzip.ID(), to.ID())
				}
			}
			sort.Strings(dependencies)
			assert.Equal(t, []string{"libc6 -> bzip2", "libc6 -> gzip"}, dependencies)
		}).
		TestCataloger(t, NewDBCataloger())
}

// when several layers are cataloged, an older copy of the status file is hidden and the newest is visible. All copies
// share an ID and collapse downstream, where the first annotation seen for a location wins. So every copy must agree
// on the evidence of the status.d location, or the merged result depends on parse completion order.
func Test_mergeStatusDirDuplicates_evidenceAgreesAcrossLayers(t *testing.T) {
	at := func(realPath, layer, visibility string) file.Location {
		return file.NewLocationFromCoordinates(file.Coordinates{RealPath: realPath, FileSystemID: layer}).
			WithAnnotation(file.VisibleAnnotationKey, visibility)
	}
	lower := dpkgTestPackageAt("gzip", "1.13-1", "arm64", at("/var/lib/dpkg/status", "sha256:lower", file.HiddenAnnotation))
	upper := dpkgTestPackageAt("gzip", "1.13-1", "arm64", at("/var/lib/dpkg/status", "sha256:upper", file.VisibleAnnotation))
	statusDir := dpkgTestPackageAt("gzip", "1.13-1", "arm64", at("/var/lib/dpkg/status.d/gzip", "sha256:base", file.VisibleAnnotation))

	got, _, err := mergeStatusDirDuplicates([]pkg.Package{lower, statusDir, upper}, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, got[0].ID(), got[1].ID())

	// a visible status entry exists, so status.d is supporting on every copy
	for i, p := range got {
		assert.Equal(t, []string{"/var/lib/dpkg/status.d/gzip"}, evidencePaths(p, pkg.SupportingEvidenceAnnotation), "status copy %d", i)
	}
}

// the same status.d entry seen in two layers is folded into one status entry. Which copy's file records win must not
// depend on map iteration order.
func Test_mergeStatusDirDuplicates_deterministicAcrossStatusDirCopies(t *testing.T) {
	statusDirInLayer := func(layer, digest string) pkg.Package {
		p := dpkgTestPackageAt("gzip", "1.13-1", "arm64",
			file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/var/lib/dpkg/status.d/gzip", FileSystemID: layer}))
		m := p.Metadata.(pkg.DpkgDBEntry)
		m.Files = []pkg.DpkgFileRecord{{Path: "/bin/gzip", Digest: &file.Digest{Algorithm: "md5", Value: digest}}}
		p.Metadata = m
		p.SetID()
		return p
	}
	input := func() []pkg.Package {
		return []pkg.Package{
			dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status"),
			statusDirInLayer("sha256:lower", "aaaa"),
			statusDirInLayer("sha256:upper", "bbbb"),
		}
	}

	first, _, err := mergeStatusDirDuplicates(input(), nil, nil)
	require.NoError(t, err)
	require.Len(t, first, 1)

	for i := 0; i < 50; i++ {
		got, _, err := mergeStatusDirDuplicates(input(), nil, nil)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, first[0].Metadata, got[0].Metadata, "run %d", i)
		require.Equal(t, first[0].ID(), got[0].ID(), "run %d", i)
	}
}

// the merge drops status.d packages and changes the ID of the status packages it folds them into, so relationships
// handed to it must be rewritten to the surviving packages rather than left pointing at IDs that no longer exist.
func Test_mergeStatusDirDuplicates_relationshipsFollowMergedPackages(t *testing.T) {
	fromStatus := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status")
	fromStatusDir := dpkgTestPackage("gzip", "1.13-1", "arm64", "/var/lib/dpkg/status.d/gzip")
	libc := dpkgTestPackage("libc6", "2.41-12", "arm64", "/var/lib/dpkg/status")

	rels := []artifact.Relationship{
		{From: libc, To: fromStatus, Type: artifact.DependencyOfRelationship},
		{From: libc, To: fromStatusDir, Type: artifact.DependencyOfRelationship},
	}

	got, gotRels, err := mergeStatusDirDuplicates([]pkg.Package{fromStatus, fromStatusDir, libc}, rels, nil)
	require.NoError(t, err)
	require.Len(t, got, 2)

	ids := make(map[artifact.ID]bool)
	for _, p := range got {
		ids[p.ID()] = true
	}
	require.NotEmpty(t, gotRels)
	for _, r := range gotRels {
		assert.True(t, ids[r.From.ID()], "relationship from %s points at a package that was not returned", r.From.ID())
		assert.True(t, ids[r.To.ID()], "relationship to %s points at a package that was not returned", r.To.ID())
	}
}
