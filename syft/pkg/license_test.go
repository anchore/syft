package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func Test_Hash(t *testing.T) {

	loc1 := source.NewLocation("place!")
	loc1.FileSystemID = "fs1"
	loc2 := source.NewLocation("place!")
	loc2.FileSystemID = "fs2" // important! there is a different file system ID

	lic1 := NewLicenseFromLocation("MIT", loc1)
	lic2 := NewLicenseFromLocation("MIT", loc2)

	hash1, err := artifact.IDByHash(lic1)
	require.NoError(t, err)

	hash2, err := artifact.IDByHash(lic2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
}
