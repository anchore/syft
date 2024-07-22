package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func TestBinaryElfRelationships(t *testing.T) {
	// node --> ["dependency of" nodes]
	expectedGraph := map[string][]string{
		"glibc": {
			"libhello_world.so",
			"syfttestfixture",
		},
		"libstdc++": {
			"syfttestfixture",
		},
		"libhello_world.so": {
			"syfttestfixture",
		},
	}

	// run the test...
	sbom, _ := catalogFixtureImage(t, "elf-test-fixtures", source.SquashedScope)

	// get a mapping of package names to their IDs
	nameToId := map[string]artifact.ID{}

	recordPkgId := func(name string) {
		pkgs := sbom.Artifacts.Packages.PackagesByName(name)
		require.NotEmpty(t, pkgs, "expected package %q to be present in the SBOM", name)
		for _, p := range pkgs {
			nameToId[p.Name] = p.ID()
		}
	}
	for name, depNames := range expectedGraph {
		recordPkgId(name)
		for _, depName := range depNames {
			recordPkgId(depName)
		}
	}

	relationshipIndex := relationship.NewIndex(sbom.Relationships...)
	for name, expectedDepNames := range expectedGraph {
		pkgId := nameToId[name]
		p := sbom.Artifacts.Packages.Package(pkgId)
		require.NotNil(t, p, "expected package %q to be present in the SBOM", name)

		rels := relationshipIndex.References(*p, artifact.DependencyOfRelationship)
		require.NotEmpty(t, rels, "expected package %q to have relationships", name)

		toIds := map[artifact.ID]struct{}{}
		for _, rel := range rels {
			toIds[rel.To.ID()] = struct{}{}
		}

		for _, depName := range expectedDepNames {
			depId := nameToId[depName]
			_, exists := toIds[depId]
			require.True(t, exists, "expected package %q to have a relationship to %q", name, depName)
		}
	}

}
