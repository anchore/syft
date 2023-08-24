package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseConanlock(t *testing.T) {
	fixture := "test-fixtures/conan.lock"
	expected := []pkg.Package{
		{
			Name:         "spdlog",
			Version:      "1.11.0",
			PURL:         "pkg:conan/spdlog@1.11.0",
			Locations:    file.NewLocationSet(file.NewLocation(fixture)),
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanLockMetadataType,
			Metadata: pkg.ConanLockMetadata{
				Ref: "spdlog/1.11.0",
				Options: map[string]string{
					"fPIC":               "True",
					"header_only":        "False",
					"no_exceptions":      "False",
					"shared":             "False",
					"wchar_filenames":    "False",
					"wchar_support":      "False",
					"fmt:fPIC":           "True",
					"fmt:header_only":    "False",
					"fmt:shared":         "False",
					"fmt:with_fmt_alias": "False",
					"fmt:with_os_api":    "True",
				},
				Path:    "conanfile.py",
				Context: "host",
			},
		},
		{
			Name:         "fmt",
			Version:      "9.1.0",
			PURL:         "pkg:conan/my_user/fmt@9.1.0?channel=my_channel",
			Locations:    file.NewLocationSet(file.NewLocation(fixture)),
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanLockMetadataType,
			Metadata: pkg.ConanLockMetadata{
				Ref: "fmt/9.1.0@my_user/my_channel#6708c9d84f98d56a6d9f2e6c2d5639ba",
				Options: map[string]string{
					"fPIC":           "True",
					"header_only":    "False",
					"shared":         "False",
					"with_fmt_alias": "False",
					"with_os_api":    "True",
				},
				Context: "host",
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseConanlock, expected, expectedRelationships)
}
