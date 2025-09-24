package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePdmLock(t *testing.T) {

	fixture := "test-fixtures/pdm-lock/pdm.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "aioboto3",
			Version:   "13.2.0",
			PURL:      "pkg:pypi/aioboto3@13.2.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Index: "https://pypi.org/simple",
				Hashes: []string{
					"sha256:fd894b8d319934dfd75285b58da35560670e57182d0148c54a3d4ee5da730c78",
					"sha256:92c3232e0bf7dcb5d921cd1eb8c5e0b856c3985f7c1cd32ab3cd51adc5c9b5da",
				},
				Summary: "Async boto3 wrapper",
			},
		},
		{
			Name:      "aiobotocore",
			Version:   "2.15.2",
			PURL:      "pkg:pypi/aiobotocore@2.15.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Index: "https://pypi.org/simple",
				Hashes: []string{
					"sha256:d4d3128b4b558e2b4c369bfa963b022d7e87303adb82eec623cec8aa77ae578a",
					"sha256:9ac1cfcaccccc80602968174aa032bf978abe36bd4e55e6781d6500909af1375",
				},
				Summary: "Async client for aws services using botocore and aiohttp",
			},
		},
	}

	expectedRelationships := []artifact.Relationship{}

	pkgtest.TestFileParser(t, fixture, parsePdmLock, expectedPkgs, expectedRelationships)
}

func Test_corruptPdmLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/pdm.lock").
		WithError().
		TestParser(t, parsePdmLock)
}
