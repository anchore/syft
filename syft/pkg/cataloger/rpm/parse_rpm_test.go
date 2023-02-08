package rpm

import (
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseRpmFiles(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/rpms",
			expected: []pkg.Package{
				{
					Name:         "abc",
					Version:      "0:1.01-9.hg20160905.el7",
					PURL:         "pkg:rpm/abc@1.01-9.hg20160905.el7?arch=x86_64&epoch=0&upstream=abc-1.01-9.hg20160905.el7.src.rpm",
					Locations:    source.NewLocationSet(source.NewLocation("abc-1.01-9.hg20160905.el7.x86_64.rpm")),
					FoundBy:      "rpm-file-cataloger",
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmMetadataType,
					Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
					Metadata: pkg.RpmMetadata{
						Name:      "abc",
						Epoch:     intRef(0),
						Arch:      "x86_64",
						Release:   "9.hg20160905.el7",
						Version:   "1.01",
						SourceRpm: "abc-1.01-9.hg20160905.el7.src.rpm",
						Size:      17396,
						License:   "MIT",
						Vendor:    "Fedora Project",
						Files: []pkg.RpmdbFileRecord{
							{"/usr/bin/abc", 33261, 7120, file.Digest{"sha256", "8f8495a65c66762b60afa0c3949d81b275ca6fa0601696caba5af762f455d0b9"}, "root", "root", ""},
							{"/usr/share/doc/abc-1.01", 16877, 4096, file.Digest{}, "root", "root", ""},
							{"/usr/share/doc/abc-1.01/readme.md", 33188, 4984, file.Digest{"sha256", "808af8a28391e96ca0d91086789488dda3724fe7c8b2859efd464fb04b94b2d4"}, "root", "root", "d"},
							{"/usr/share/doc/abc-1.01/readmeaig", 33188, 3324, file.Digest{"sha256", "530ec6175cf7fbeb7b595cbe7a50994429c4e62cae6666fb3a1d5745f3127b19"}, "root", "root", "d"},
							{"/usr/share/man/man1/abc.1.gz", 33188, 1968, file.Digest{"sha256", "cf2cfe25b29087e60ffd5f31f974a0762172fc2f009704951f12ff750ea77ed6"}, "root", "root", "d"},
						},
					},
				},
				{
					Name:         "zork",
					Version:      "0:1.0.3-1.el7",
					PURL:         "pkg:rpm/zork@1.0.3-1.el7?arch=x86_64&epoch=0&upstream=zork-1.0.3-1.el7.src.rpm",
					Locations:    source.NewLocationSet(source.NewLocation("zork-1.0.3-1.el7.x86_64.rpm")),
					FoundBy:      "rpm-file-cataloger",
					Type:         pkg.RpmPkg,
					MetadataType: pkg.RpmMetadataType,
					Licenses:     internal.LogicalStrings{Simple: []string{"Public Domain"}},
					Metadata: pkg.RpmMetadata{
						Name:      "zork",
						Epoch:     intRef(0),
						Arch:      "x86_64",
						Release:   "1.el7",
						Version:   "1.0.3",
						SourceRpm: "zork-1.0.3-1.el7.src.rpm",
						Size:      262367,
						License:   "Public Domain",
						Vendor:    "Fedora Project",
						Files: []pkg.RpmdbFileRecord{
							{"/usr/bin/zork", 33261, 115440, file.Digest{"sha256", "31b2ffc20b676a8fff795a45308f584273b9c47e8f7e196b4f36220b2734b472"}, "root", "root", ""},
							{"/usr/share/doc/zork-1.0.3", 16877, 38, file.Digest{}, "root", "root", ""},
							{"/usr/share/doc/zork-1.0.3/README.md", 33188, 5123, file.Digest{"sha256", "0013d67610a80c9f62d151a952f18d520b15b4c505b3ec2af34b96ab824654a4"}, "root", "root", "d"},
							{"/usr/share/doc/zork-1.0.3/history", 33188, 4816, file.Digest{"sha256", "6949044a65adefca6ac0132c18cfccc4ba8fdaec948424b6ccb60afd8a6ac82f"}, "root", "root", "d"},
							{"/usr/share/licenses/zork-1.0.3", 16877, 24, file.Digest{}, "root", "root", ""},
							{"/usr/share/licenses/zork-1.0.3/readme.txt", 33188, 146, file.Digest{"sha256", "9d6f7500555a2ecc3cb289dcca1e37fb96894dab1e4ba692b4d36fd6c3bdf939"}, "root", "root", "l"},
							{"/usr/share/man/man6/dungeon.6.gz", 33188, 3800, file.Digest{"sha256", "9b065d6a6f65b4d2d038fcca0af47a38e8723c32008d08659739ac34abe018da"}, "root", "root", "d"},
							{"/usr/share/man/man6/zork.6.gz", 33188, 34, file.Digest{"sha256", "18fbcb598bc40a25befe26256e29366984d2288dd154f877b8ac5fc138dd0884"}, "root", "root", "d"},
							{"/usr/share/zork/dtextc.dat", 33188, 133008, file.Digest{"sha256", "25ca42857c2b32054916d9258152293ead644023d5e03bec039ea92014e2ef91"}, "root", "root", ""},
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/bad",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expected, nil).
				TestCataloger(t, NewFileCataloger())
		})
	}
}
