package integration

import (
	"sort"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestDpkgStatusAndStatusDir(t *testing.T) {
	// the fixture image lists gzip in both /var/lib/dpkg/status and /var/lib/dpkg/status.d/gzip, bzip2 only in
	// status.d, and libc6 only in status. The status file is written by two layers. A package described
	// by both files must be reported once, whichever layers are cataloged.
	expected := []string{
		"bzip2@1.0.8-6+dhi2",
		"gzip@1.13-1+dhi1",
		"libc6@2.41-12+deb13u3+dhi1",
	}

	for _, scope := range []source.Scope{source.SquashedScope, source.AllLayersScope, source.DeepSquashedScope} {
		t.Run(string(scope), func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, "image-dpkg-status-and-status-d", scope)

			var got []string
			for _, p := range sbom.Artifacts.Packages.Sorted(pkg.DebPkg) {
				got = append(got, p.Name+"@"+p.Version)
			}
			sort.Strings(got)

			assert.Equal(t, expected, got)

			// gzip keeps status as its only primary evidence, with status.d supporting it
			gzip := sbom.Artifacts.Packages.PackagesByName("gzip")
			require.Len(t, gzip, 1)
			assert.Equal(t, []string{"/var/lib/dpkg/status"}, evidencePaths(gzip[0], pkg.PrimaryEvidenceAnnotation))
			assert.Equal(t, []string{"/var/lib/dpkg/status.d/gzip"}, evidencePaths(gzip[0], pkg.SupportingEvidenceAnnotation))

			// and the dependency on libc6 points at the package that was reported, not a copy from before the merge
			var dependents []artifact.ID
			for _, r := range sbom.Relationships {
				from, ok := r.From.(pkg.Package)
				if r.Type != artifact.DependencyOfRelationship || !ok || from.Name != "libc6" {
					continue
				}
				dependents = append(dependents, r.To.ID())
			}
			assert.Contains(t, dependents, gzip[0].ID())
			for _, id := range dependents {
				assert.NotNil(t, sbom.Artifacts.Packages.Package(id), "libc6 is a dependency of a package that is not in the SBOM")
			}
		})
	}
}

// evidencePaths returns the distinct location paths of a package carrying the given evidence annotation.
func evidencePaths(p pkg.Package, evidence string) []string {
	paths := strset.New()
	for _, l := range p.Locations.ToSlice() {
		if l.Annotations[pkg.EvidenceAnnotationKey] == evidence {
			paths.Add(l.RealPath)
		}
	}
	list := paths.List()
	sort.Strings(list)
	return list
}
