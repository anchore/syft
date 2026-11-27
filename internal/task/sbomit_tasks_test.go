package task

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sbomit/sbomit/pkg/resolve"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// an in-toto statement recording the files opened by a build that installed six@1.16.0 and attrs@26.1.0
const sbomitTestAttestation = `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
  "predicate": {
    "name": "build",
    "attestations": [{
      "type": "https://witness.dev/attestations/command-run/v0.1",
      "attestation": {
        "cmd": [],
        "processes": [{
          "openedfiles": {
            "/venv/lib/python3.12/site-packages/six-1.16.0.dist-info/METADATA": {"sha256": "0000000000000000000000000000000000000000000000000000000000000001"},
            "/venv/lib/python3.12/site-packages/attrs-26.1.0.dist-info/METADATA": {"sha256": "0000000000000000000000000000000000000000000000000000000000000002"}
          }
        }]
      }
    }]
  }
}`

func Test_sbomitTask_VerifyAndAddPackages(t *testing.T) {
	t.Chdir(t.TempDir())
	attestation := file.NewLocation("build.attestation.json")
	require.NoError(t, os.WriteFile(attestation.RealPath, []byte(sbomitTestAttestation), 0o600))

	cataloged := pkg.Package{Name: "six", Version: "1.16.0", Type: pkg.PythonPkg}
	cataloged.SetID()
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(cataloged)}}

	tsk := NewSBOMitTask(CatalogingFactoryConfig{})
	require.NoError(t, tsk.Execute(context.Background(), file.NewMockResolverForPaths(attestation.RealPath), sbomsync.NewBuilder(s)))

	relatedToAttestation := func(id artifact.ID) bool {
		return slices.ContainsFunc(s.Relationships, func(r artifact.Relationship) bool {
			return r.From.ID() == id && r.To.ID() == attestation.Coordinates.ID()
		})
	}

	// a package already cataloged is related to the attestation, not duplicated
	assert.Len(t, s.Artifacts.Packages.PackagesByName("six"), 1)
	assert.True(t, relatedToAttestation(cataloged.ID()), "the cataloged package must be related to the attestation")

	// a package only the attestation knows of is added, and related to it
	added := s.Artifacts.Packages.PackagesByName("attrs")
	require.Len(t, added, 1)
	assert.Equal(t, "26.1.0", added[0].Version)
	assert.Equal(t, pkg.PythonPkg, added[0].Type)
	assert.Equal(t, "sbomit", added[0].FoundBy)
	assert.True(t, relatedToAttestation(added[0].ID()), "the added package must be related to the attestation")
}

func Test_shouldAdd(t *testing.T) {
	path := func(pkgMgr string) resolve.Evidence {
		return resolve.Evidence{Source: resolve.SourcePath, PkgMgr: pkgMgr}
	}
	download := func(pkgMgr string, artifact bool) resolve.Evidence {
		return resolve.Evidence{Source: resolve.SourceNetwork, PkgMgr: pkgMgr, Artifact: artifact}
	}

	tests := []struct {
		name      string
		ecosystem string
		evidence  []resolve.Evidence
		want      bool
	}{
		{name: "installed, seen on disk", ecosystem: "pypi", evidence: []resolve.Evidence{path("pip"), download("pip", true)}, want: true},
		{name: "fetched by pip, never installed", ecosystem: "pypi", evidence: []resolve.Evidence{download("pip", true)}, want: false},
		{name: "fetched by gradle, never installed", ecosystem: "maven", evidence: []resolve.Evidence{download("gradle", true)}, want: false},
		{name: "fetched by pnpm, whose store paths carry versions", ecosystem: "npm", evidence: []resolve.Evidence{download("pnpm", true)}, want: false},
		{name: "tarball downloaded by npm", ecosystem: "npm", evidence: []resolve.Evidence{download("npm", true)}, want: true},
		{name: "only npm registry metadata", ecosystem: "npm", evidence: []resolve.Evidence{download("npm", false)}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldAdd(resolve.Package{Ecosystem: tt.ecosystem, Evidence: tt.evidence}))
		})
	}
}
