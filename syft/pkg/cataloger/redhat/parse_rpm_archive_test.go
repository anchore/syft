package redhat

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRpmFiles(t *testing.T) {
	ctx := context.TODO()
	abcRpmLocation := file.NewLocation("abc-1.01-9.hg20160905.el7.x86_64.rpm")
	zorkRpmLocation := file.NewLocation("zork-1.0.3-1.el7.x86_64.rpm")
	tests := []struct {
		name         string
		fixtureDir   string
		fixtureImage string
		skipFiles    bool
		expected     []pkg.Package
	}{
		{
			name:       "go case",
			fixtureDir: "test-fixtures/rpms",
			expected: []pkg.Package{
				{
					Name:      "abc",
					Version:   "0:1.01-9.hg20160905.el7",
					PURL:      "pkg:rpm/abc@1.01-9.hg20160905.el7?arch=x86_64&epoch=0&upstream=abc-1.01-9.hg20160905.el7.src.rpm",
					Locations: file.NewLocationSet(file.NewLocation("abc-1.01-9.hg20160905.el7.x86_64.rpm")),
					FoundBy:   "rpm-archive-cataloger",
					Type:      pkg.RpmPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", abcRpmLocation),
					),
					Metadata: pkg.RpmArchive{
						Name:      "abc",
						Epoch:     intRef(0),
						Arch:      "x86_64",
						Release:   "9.hg20160905.el7",
						Version:   "1.01",
						SourceRpm: "abc-1.01-9.hg20160905.el7.src.rpm",
						Signatures: []pkg.RpmSignature{
							{
								PublicKeyAlgorithm: "RSA",
								HashAlgorithm:      "SHA256",
								Created:            "Wed Sep 21 07:09:44 2016",
								IssuerKeyID:        "6a2faea2352c64e5",
							},
						},
						Size:   17396,
						Vendor: "Fedora Project",
						Files: []pkg.RpmFileRecord{
							{"/usr/bin/abc", 33261, 7120, file.Digest{"sha256", "8f8495a65c66762b60afa0c3949d81b275ca6fa0601696caba5af762f455d0b9"}, "root", "root", ""},
							{"/usr/share/doc/abc-1.01", 16877, 4096, file.Digest{}, "root", "root", ""},
							{"/usr/share/doc/abc-1.01/readme.md", 33188, 4984, file.Digest{"sha256", "808af8a28391e96ca0d91086789488dda3724fe7c8b2859efd464fb04b94b2d4"}, "root", "root", "d"},
							{"/usr/share/doc/abc-1.01/readmeaig", 33188, 3324, file.Digest{"sha256", "530ec6175cf7fbeb7b595cbe7a50994429c4e62cae6666fb3a1d5745f3127b19"}, "root", "root", "d"},
							{"/usr/share/man/man1/abc.1.gz", 33188, 1968, file.Digest{"sha256", "cf2cfe25b29087e60ffd5f31f974a0762172fc2f009704951f12ff750ea77ed6"}, "root", "root", "d"},
						},
					},
				},
				{
					Name:      "zork",
					Version:   "0:1.0.3-1.el7",
					PURL:      "pkg:rpm/zork@1.0.3-1.el7?arch=x86_64&epoch=0&upstream=zork-1.0.3-1.el7.src.rpm",
					Locations: file.NewLocationSet(zorkRpmLocation),
					FoundBy:   "rpm-archive-cataloger",
					Type:      pkg.RpmPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocationsWithContext(ctx, "Public Domain", zorkRpmLocation),
					),
					Metadata: pkg.RpmArchive{
						Name:      "zork",
						Epoch:     intRef(0),
						Arch:      "x86_64",
						Release:   "1.el7",
						Version:   "1.0.3",
						SourceRpm: "zork-1.0.3-1.el7.src.rpm",
						Size:      262367,
						Signatures: []pkg.RpmSignature{
							{
								PublicKeyAlgorithm: "RSA",
								HashAlgorithm:      "SHA256",
								Created:            "Tue Mar  2 17:32:21 2021",
								IssuerKeyID:        "6a2faea2352c64e5",
							},
						},
						Vendor: "Fedora Project",
						Files: []pkg.RpmFileRecord{
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
			name:       "bad rpms",
			fixtureDir: "test-fixtures/bad",
		},
		{
			name:         "rpms with signatures from RSA header",
			fixtureImage: "image-rpm-archive",
			skipFiles:    true,
			expected: []pkg.Package{
				{
					Name:      "postgresql14-server",
					Version:   "0:14.10-1PGDG.rhel9",
					PURL:      "pkg:rpm/postgresql14-server@14.10-1PGDG.rhel9?arch=x86_64&epoch=0&upstream=postgresql14-14.10-1PGDG.rhel9.src.rpm",
					Locations: file.NewLocationSet(file.NewLocation("/postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm")),
					FoundBy:   "rpm-archive-cataloger",
					Type:      pkg.RpmPkg,
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocations("PostgreSQL", file.NewLocation("/postgresql14-server-14.10-1PGDG.rhel9.x86_64.rpm"))),
					Language:  "",
					CPEs:      nil,
					Metadata: pkg.RpmArchive{
						Name:      "postgresql14-server",
						Version:   "14.10",
						Epoch:     ref(0),
						Arch:      "x86_64",
						Release:   "1PGDG.rhel9",
						SourceRpm: "postgresql14-14.10-1PGDG.rhel9.src.rpm",
						Size:      24521699,
						Signatures: []pkg.RpmSignature{
							{
								PublicKeyAlgorithm: "RSA",
								HashAlgorithm:      "SHA256",
								Created:            "Tue Jan  2 16:45:56 2024",
								IssuerKeyID:        "40bca2b408b40d20",
							},
						},
						Vendor: "PostgreSQL Global Development Group",
						// note: files are not asserted in this test
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var opts []cmp.Option
			if test.skipFiles {
				opts = append(opts, cmpopts.IgnoreFields(pkg.RpmArchive{}, "Files"))
			}
			pkgtest.NewCatalogTester().
				WithCompareOptions(opts...).
				FromDirectory(t, test.fixtureDir).
				WithImageResolver(t, test.fixtureImage).
				IgnoreLocationLayer().
				Expects(test.expected, nil).
				TestCataloger(t, NewArchiveCataloger())
		})
	}
}

func Test_parseRSA(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    *pkg.RpmSignature
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "older RSA header",
			data: "89021503050058d3e39b0946fca2c105b9de0102b12a1000a2b3d347b51142e83b2de5e03ba9096f6330b72c140e46200d662b01c78534d14fab2ad4f07325119386830dd590219f27a22e420680283c500c40e6fba95404884b0a0abca8f198030ddc03653b7db2883b8230687e9e73d43eb5a24dbabfa48bbb3d1151ed264744e5e8ca169b0c4673a1440a9b99e53e693c9722f6423833cd7795e3044227fb922e21b7c007f03e923fae3f04d1ac2e8581e68c6790115b6dccfc02c8cb41681ed84785df086d6e26008c257d088a524ba2e7a7a5f41ad26b106c67b87fe48118b69662db612c23d2140059286f1ba7764627def6867ad0e11fe3a01fb1422dabe6f5cdf4cd876dc4fadfd2364bc3ba3758db94aaf3b82368cba65cf762287f713eb7ddc773acf93b083c739577a7eaf1f99e7dcbb8db1da050490e9fb67c838448db060a9e619d318c96f03e4363808d84ce29e8c102c290cc2bfab5746f3d9ddc9eb8b428f3ad2678abb2d46e846ddca7fc41322d76a97be6d416b4750f23320ec725e082be4496483b4cd3a3d2c515b3c8a6e27541139d809245140303877b84842ed2dd0454a78b2dfb7d6213784697077a8167942ebda5995a28d8256957e33e301706c35944ae05c7a54a4dd89be654d26cefa5cf0f616bbeaf317138371b09c5bbd5531f716020e553354ce5dbce3d9bb72f21e1857408dfd5a35250ff40f61ae1e25409ae9d21db76b8878341f4762a22be2189",
			// RSA/SHA1, Thu Mar 23 15:02:51 2017, Key ID 0946fca2c105b9de
			want: &pkg.RpmSignature{
				PublicKeyAlgorithm: "RSA",
				HashAlgorithm:      "SHA1",
				Created:            "Thu Mar 23 15:02:51 2017",
				IssuerKeyID:        "0946fca2c105b9de",
			},
		},
		{
			name: "newer RSA header",
			data: "89024a04000108003416210421cb256ae16fc54c6e652949702d426d350d275d050262804369161c72656c656e6740726f636b796c696e75782e6f7267000a0910702d426d350d275dc8910ffd14f0f80297481fea648e7ba5a74bce10c5faccc2bbe588caece04be34d304a6a445538afc97a7033d43c983d27cc8f5ee515b2dd92f3e03354c413e55372a4d19386eb0f2354f9a26ee5fc2e56dfda49555e4a58b49279b70cd2036b04f28125f85942f640f2984e29e079f26bf6f76831d83d95983aa084a3e7b6327be2e23d0d799c4b4d1cfb36147ddfb782bf9df7b331d97f4f46b38f968b6130d87b0ef6bb0d424390fe34e38092babed37440569a93f55f50a2bdb58be0259f35badf7e728bd49824ed47f69fa53b6e26736bde4d8358d959b090e88054c3e179745dc7377e41b54b4e10223f4859e88162c7c5ec64b78d36cf8a914c1c2deb8c4f19a70d406e70756a89195d6aee488a9b40b9dbb76b2c38e528eb88d08ec35774a48ed9ce4e0dfac45cb7613ad5921f54c61d3aae5d7b3ab0e2e6ff867ac8f395b37af78b5c01022a4a4e62f7a99425fccb7439880cd6b393a3050b2e9512693bc36f6fe9de2921dda59710a1508965065244cf9f0f8cfc5bd554777f1a84d2249339234d62f2441249f617ad7df4fb01367a91d3a880e86fdb84bc6d03a127b44a28c6ceadef89e438db9640aa59b8a3f460b07272511f8187a5f3b163c8fd1caa61667401bce2ccdb1c176c46be10ef8033903132cca5889fa3661b2fba590c41fa1c104c08426677bdbf745a52ccd28f581960cf9d7e4ede3b9584aacb2f20ef93",
			// RSA/SHA256, Sun May 15 00:03:53 2022, Key ID 702d426d350d275d
			want: &pkg.RpmSignature{
				PublicKeyAlgorithm: "RSA",
				HashAlgorithm:      "SHA256",
				Created:            "Sun May 15 00:03:53 2022",
				IssuerKeyID:        "702d426d350d275d",
			},
		},
		{
			name: "example from rocky9",
			data: "8901b304000108001d162104d4bf08ae67a0b4c7a1dbccd240bca2b408b40d20050265943dc4000a091040bca2b408b40d203b270bff71678ffeb190833a19a82112f59eee64cba186ab454d4526e0b3c8797e723f6916daff1b1f18cbf53c0da5d398a3a42065e79e5ca939f721652f38400dd4cac1107a902b1dae880649437ad0242444f3f07115172cae0a207b7cf8340af2f4a94976325f1dc165d5c2a564be322c4e130adb6217e7138b689f08898c407b223aa1ff8f8d592f31eba2256c02fae70ce4022d688a487972646b8bf1b518b5d6549c1e60fd812134422d9fdb41cf799f5eab80e48b4ab7cff84362dc867ed1af1416dd78e92bcc59217de7064b9a015d94a5097788689b9b6fbdeea679cfe4a6947f73dc3a6c810f2cb999d279b01564422d1500fc1bd8bd1eefa2d60660127ffef24067354660f93c0faf81f4edd599dd7e4b77fe4bff6c7a0ea83530c817c38d1f2364175883c6ef7b6dec86ad282bdd5138b8597567db96810c4ed6454a4ab1d98f0425dcd8892a5d46ed9289cb3ae3e1f1e2663d3e8188e873428f6cf7163563ed3860edc4fee81522389508847e692e2d13310eb4b40f7fdd7eb364a0b2dc",
			// RSA/SHA256, Tue Jan  2 16:45:56 2024, Key ID 40bca2b408b40d20
			want: &pkg.RpmSignature{
				PublicKeyAlgorithm: "RSA",
				HashAlgorithm:      "SHA256",
				Created:            "Tue Jan  2 16:45:56 2024",
				IssuerKeyID:        "40bca2b408b40d20",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			data, err := hex.DecodeString(tt.data)
			require.NoError(t, err)

			got, err := parsePGP(data)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func ref[T any](v T) *T {
	return &v
}

func Test_corruptRpmArchive(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/bad/bad.rpm").
		WithError().
		TestParser(t, parseRpmArchive)
}
