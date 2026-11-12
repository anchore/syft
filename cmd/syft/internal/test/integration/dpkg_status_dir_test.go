package integration

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestDpkgStatusAndStatusDir(t *testing.T) {
	// the fixture image lists gzip in both /var/lib/dpkg/status and /var/lib/dpkg/status.d/gzip, bzip2 only in
	// status.d, and libc6 and tzdata only in status. The status file is written by two layers. A package described
	// by both files must be reported once, whichever layers are cataloged.
	expected := []string{
		"bzip2@1.0.8-6+dhi2",
		"gzip@1.13-1+dhi1",
		"libc6@2.41-12+deb13u3+dhi1",
		"tzdata@2026b-0+deb13u1+dhi2",
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
		})
	}
}
