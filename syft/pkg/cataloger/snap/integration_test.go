package snap

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func TestRealDpkgYamlParsing(t *testing.T) {
	fixture := "test-fixtures/real-dpkg.yaml"

	// Open the file
	f, err := os.Open(fixture)
	require.NoError(t, err)
	defer f.Close()

	reader := file.LocationReadCloser{
		Location:   file.NewLocation(fixture),
		ReadCloser: f,
	}

	// Parse using our function
	packages, relationships, err := parseBaseDpkgYaml(context.Background(), nil, &generic.Environment{}, reader)

	require.NoError(t, err)
	assert.Nil(t, relationships) // relationships should be nil for this parser

	// We should have 10 packages from the fixture
	assert.Equal(t, 10, len(packages))

	// Check some specific packages
	foundPackages := make(map[string]pkg.Package)
	for _, p := range packages {
		foundPackages[p.Name] = p
	}

	// Verify key packages exist
	require.Contains(t, foundPackages, "adduser")
	require.Contains(t, foundPackages, "systemd")
	require.Contains(t, foundPackages, "gcc-10-base")

	// Check that architecture is parsed correctly from package names
	gccPkg := foundPackages["gcc-10-base"]
	metadata, ok := gccPkg.Metadata.(pkg.SnapEntry)
	require.True(t, ok)
	assert.Equal(t, "amd64", metadata.Architecture)
	assert.Equal(t, pkg.SnapTypeBase, metadata.SnapType)
}
