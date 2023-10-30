package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseConaninfo(t *testing.T) {
	fixture := "test-fixtures/conaninfo/mfast/1.2.2/my_user/my_channel/package/9d1f076b471417647c2022a78d5e2c1f834289ac/conaninfo.txt"
	expected := []pkg.Package{
		{
			Name:      "mfast",
			Version:   "1.2.2",
			PURL:      "pkg:conan/my_user/mfast@1.2.2?channel=my_channel",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "mfast/1.2.2@my_user/my_channel#c6f6387c9b99780f0ee05e25f99d0f39",
				PackageID: "9d1f076b471417647c2022a78d5e2c1f834289ac",
			},
		},
		{
			Name:      "boost",
			Version:   "1.75.0",
			PURL:      "pkg:conan/boost@1.75.0",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "boost/1.75.0:dc8aedd23a0f0a773a5fcdcfe1ae3e89c4205978",
				PackageID: "dc8aedd23a0f0a773a5fcdcfe1ae3e89c4205978",
			},
		},
		{
			Name:      "zlib",
			Version:   "1.2.13",
			PURL:      "pkg:conan/zlib@1.2.13",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "zlib/1.2.13:dfbe50feef7f3c6223a476cd5aeadb687084a646",
				PackageID: "dfbe50feef7f3c6223a476cd5aeadb687084a646",
			},
		},
		{
			Name:      "bzip2",
			Version:   "1.0.8",
			PURL:      "pkg:conan/bzip2@1.0.8",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "bzip2/1.0.8:c32092bf4d4bb47cf962af898e02823f499b017e",
				PackageID: "c32092bf4d4bb47cf962af898e02823f499b017e",
			},
		},
		{
			Name:      "libbacktrace",
			Version:   "cci.20210118",
			PURL:      "pkg:conan/libbacktrace@cci.20210118",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "libbacktrace/cci.20210118:dfbe50feef7f3c6223a476cd5aeadb687084a646",
				PackageID: "dfbe50feef7f3c6223a476cd5aeadb687084a646",
			},
		},
		{
			Name:      "tinyxml2",
			Version:   "9.0.0",
			PURL:      "pkg:conan/tinyxml2@9.0.0",
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
			Language:  pkg.CPP,
			Type:      pkg.ConanPkg,
			Metadata: pkg.ConaninfoEntry{
				Ref:       "tinyxml2/9.0.0:6557f18ca99c0b6a233f43db00e30efaa525e27e",
				PackageID: "6557f18ca99c0b6a233f43db00e30efaa525e27e",
			},
		},
	}

	// relationships require IDs to be set to be sorted similarly
	for i := range expected {
		expected[i].SetID()
	}

	var expectedRelationships = []artifact.Relationship{
		{
			From: expected[1], // boost
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[5], // tinyxml2
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[2], // zlib
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[3], // bzip2
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: expected[4], // libbacktrace
			To:   expected[0], // mfast
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseConaninfo, expected, expectedRelationships)
}
