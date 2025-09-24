package sqlitetest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
)

func Test_noSQLiteDriverError(t *testing.T) {
	// this test package does must not import the sqlite library
	file := "../test-fixtures/Packages"
	resolver, err := fileresolver.NewFromFile(file, file)
	require.NoError(t, err)

	cataloger := redhat.NewDBCataloger()
	_, _, err = cataloger.Catalog(context.TODO(), resolver)
	require.ErrorContains(t, err, "sqlite")
}
