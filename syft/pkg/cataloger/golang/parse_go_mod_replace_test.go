package golang

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func Test_parseGoSource_replacedModulesAreNotDuplicated(t *testing.T) {
	fixture := filepath.Join("testdata", "go-source-replacements")
	s, err := directorysource.NewFromPath(fixture)
	require.NoError(t, err)
	resolver, err := s.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	modPath, err := filepath.Abs(filepath.Join(fixture, "go.mod"))
	require.NoError(t, err)
	contents, err := os.Open(modPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, contents.Close()) })

	reader := file.LocationReadCloser{
		Location:   file.NewVirtualLocationFromDirectory("go.mod", "go.mod", *stereofile.NewFileReference(stereofile.Path(modPath))),
		ReadCloser: contents,
	}
	config := DefaultCatalogerConfig().WithUsePackagesLib(true).WithSearchRemoteLicenses(false)
	pkgs, _, err := newGoModCataloger(config).parseGoModFile(pkgtest.Context(t), resolver, nil, reader)
	require.NoError(t, err)

	versions := make(map[string][]string)
	for _, p := range pkgs {
		versions[p.Name] = append(versions[p.Name], p.Version)
	}
	require.Equal(t, []string{"v1.5.2"}, versions["rsc.io/quote"])
	require.Equal(t, []string{"v1.3.1"}, versions["rsc.io/sampler"])
}
