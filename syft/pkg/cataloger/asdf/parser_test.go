package asdf

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/stretchr/testify/require"
)

func Test_AsdfCataloger(t *testing.T) {
	src, err := directorysource.NewFromPath("test-fixtures")
	require.NoError(t, err)

	res, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	pkgtest.NewCatalogTester().
		ExpectsPackageStrings([]string{"curl @ 5.2.1 (.asdf/installs/curl/5.2.1/bin/curl)"}).
		WithResolver(res).
		TestCataloger(t, NewInstalledFileCataloger())
}
