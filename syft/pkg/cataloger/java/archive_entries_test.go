package java

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

// java tooling doesn't agree on case ("meta-inf/LICENSE", "LIB.JAR"), and the license, version and
// nested-archive lookups have always matched regardless of it
func Test_archiveEntries_globFoldIgnoresCase(t *testing.T) {
	names := []string{"meta-inf/LICENSE.txt", "Version.Properties", "lib/DEP.JAR", "META-INF/MANIFEST.MF"}

	archivePath := filepath.Join(t.TempDir(), "app.jar")
	f, err := os.Create(archivePath)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	for _, name := range names {
		_, err := zw.Create(name)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	fromZip, err := newZipEntries(context.Background(), archivePath)
	require.NoError(t, err)

	var rooted []string
	for _, name := range names {
		rooted = append(rooted, "/"+name)
	}
	fromResolver := &resolverEntries{resolver: file.NewMockResolverForPaths(rooted...)}

	for name, entries := range map[string]archiveEntries{"zip": fromZip, "resolver": fromResolver} {
		t.Run(name, func(t *testing.T) {
			assert.ElementsMatch(t, []string{"meta-inf/LICENSE.txt", "META-INF/MANIFEST.MF"}, entries.globFold("/META-INF/*"))
			assert.Equal(t, []string{"Version.Properties"}, entries.globFold("/version.properties"))
			assert.Equal(t, []string{"lib/DEP.JAR"}, entries.globFold("**/*.jar", "**/*.war"))
			assert.Empty(t, entries.glob("/version.properties"), "glob itself stays case-sensitive")
		})
	}
}
