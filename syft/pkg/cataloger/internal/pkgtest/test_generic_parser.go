package pkgtest

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

func TestGenericParser(t *testing.T, fixturePath string, parser generic.Parser, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	TestGenericParserWithEnv(t, fixturePath, parser, nil, expectedPkgs, expectedRelationships)
}

func TestGenericParserWithEnv(t *testing.T, fixturePath string, parser generic.Parser, env *generic.Environment, expectedPkgs []pkg.Package, expectedRelationships []artifact.Relationship) {
	fixture, err := os.Open(fixturePath)
	require.NoError(t, err)

	actualPkgs, actualRelationships, err := parser(nil, env, source.LocationReadCloser{
		Location:   source.NewLocation(fixture.Name()),
		ReadCloser: fixture,
	})
	require.NoError(t, err)

	AssertPackagesEqual(t, expectedPkgs, actualPkgs)

	if diff := cmp.Diff(expectedRelationships, actualRelationships); diff != "" {
		t.Errorf("unexpected relationships from parsing (-expected +actual)\n%s", diff)
	}
}
