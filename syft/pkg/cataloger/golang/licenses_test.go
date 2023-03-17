package golang

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
)

func Test_LicenseSearch(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := path.Join(wd, "test-fixtures", "licenses")
	err = os.Setenv("GOPATH", dir)
	require.NoError(t, err)

	l := newGoLicenses(true)
	licenses, err := l.getLicenses(source.MockResolver{}, "github.com/someorg/somename", "v0.3.2")
	require.NoError(t, err)

	require.Len(t, licenses, 1)

	require.Equal(t, "Apache-2.0", licenses[0])
}
