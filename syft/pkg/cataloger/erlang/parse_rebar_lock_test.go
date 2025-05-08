package erlang

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRebarLock(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/rebar.lock",
			expected: []pkg.Package{
				{
					Name:     "certifi",
					Version:  "2.9.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/certifi@2.9.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "certifi",
						Version:    "2.9.0",
						PkgHash:    "6F2A475689DD47F19FB74334859D460A2DC4E3252A3324BD2111B8F0429E7E21",
						PkgHashExt: "266DA46BDB06D6C6D35FDE799BCB28D36D985D424AD7C08B5BB48F5B5CDD4641",
					},
				},
				{
					Name:     "idna",
					Version:  "6.1.1",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/idna@6.1.1",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "idna",
						Version:    "6.1.1",
						PkgHash:    "8A63070E9F7D0C62EB9D9FCB360A7DE382448200FBBD1B106CC96D3D8099DF8D",
						PkgHashExt: "92376EB7894412ED19AC475E4A86F7B413C1B9FBB5BD16DCCD57934157944CEA",
					},
				},
				{
					Name:     "metrics",
					Version:  "1.0.1",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/metrics@1.0.1",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "metrics",
						Version:    "1.0.1",
						PkgHash:    "25F094DEA2CDA98213CECC3AEFF09E940299D950904393B2A29D191C346A8486",
						PkgHashExt: "69B09ADDDC4F74A40716AE54D140F93BEB0FB8978D8636EADED0C31B6F099F16",
					},
				},
				{
					Name:     "mimerl",
					Version:  "1.2.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/mimerl@1.2.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "mimerl",
						Version:    "1.2.0",
						PkgHash:    "67E2D3F571088D5CFD3E550C383094B47159F3EEE8FFA08E64106CDF5E981BE3",
						PkgHashExt: "F278585650AA581986264638EBF698F8BB19DF297F66AD91B18910DFC6E19323",
					},
				},
				{
					Name:     "parse_trans",
					Version:  "3.3.1",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/parse_trans@3.3.1",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "parse_trans",
						Version:    "3.3.1",
						PkgHash:    "16328AB840CC09919BD10DAB29E431DA3AF9E9E7E7E6F0089DD5A2D2820011D8",
						PkgHashExt: "07CD9577885F56362D414E8C4C4E6BDF10D43A8767ABB92D24CBE8B24C54888B",
					},
				},
				{
					Name:     "ssl_verify_fun",
					Version:  "1.1.6",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/ssl_verify_fun@1.1.6",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "ssl_verify_fun",
						Version:    "1.1.6",
						PkgHash:    "CF344F5692C82D2CD7554F5EC8FD961548D4FD09E7D22F5B62482E5AEAEBD4B0",
						PkgHashExt: "BDB0D2471F453C88FF3908E7686F86F9BE327D065CC1EC16FA4540197EA04680",
					},
				},
				{
					Name:     "unicode_util_compat",
					Version:  "0.7.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/unicode_util_compat@0.7.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "unicode_util_compat",
						Version:    "0.7.0",
						PkgHash:    "BC84380C9AB48177092F43AC89E4DFA2C6D62B40B8BD132B1059ECC7232F9A78",
						PkgHashExt: "25EEE6D67DF61960CF6A794239566599B09E17E668D3700247BC498638152521",
					},
				},
			},
		},
		{
			fixture: "test-fixtures/rebar-2.lock",
			expected: []pkg.Package{
				//[{<<"bcrypt">>,{pkg,<<"bcrypt">>,<<"1.1.5">>},0},
				// {<<"bcrypt">>, <<"A6763BD4E1AF46D34776F85B7995E63A02978DE110C077E9570ED17006E03386">>},
				// {<<"bcrypt">>, <<"3418821BC17CE6E96A4A77D1A88D7485BF783E212069FACFC79510AFBFF95352">>},
				{
					Name:     "bcrypt",
					Version:  "1.1.5",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/bcrypt@1.1.5",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "bcrypt",
						Version:    "1.1.5",
						PkgHash:    "A6763BD4E1AF46D34776F85B7995E63A02978DE110C077E9570ED17006E03386",
						PkgHashExt: "3418821BC17CE6E96A4A77D1A88D7485BF783E212069FACFC79510AFBFF95352",
					},
				},
				// {<<"bson">>,
				//  {git,"https://github.com/comtihon/bson-erlang",
				//       {ref,"14308ab927cfa69324742c3de720578094e0bb19"}},
				//  1},
				{
					Name:     "bson",
					Version:  "14308ab927cfa69324742c3de720578094e0bb19",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/bson@14308ab927cfa69324742c3de720578094e0bb19",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:    "bson",
						Version: "14308ab927cfa69324742c3de720578094e0bb19",
					},
				},
				// {<<"certifi">>,{pkg,<<"certifi">>,<<"2.9.0">>},1},
				// {<<"certifi">>, <<"6F2A475689DD47F19FB74334859D460A2DC4E3252A3324BD2111B8F0429E7E21">>}, {<<"stdout_formatter">>, <<"EC24868D8619757A68F0798357C7190807A1CFC42CE90C18C23760E59249A21A">>},
				// {<<"certifi">>, <<"266DA46BDB06D6C6D35FDE799BCB28D36D985D424AD7C08B5BB48F5B5CDD4641">>},
				{
					Name:     "certifi",
					Version:  "2.9.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/certifi@2.9.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "certifi",
						Version:    "2.9.0",
						PkgHash:    "6F2A475689DD47F19FB74334859D460A2DC4E3252A3324BD2111B8F0429E7E21",
						PkgHashExt: "266DA46BDB06D6C6D35FDE799BCB28D36D985D424AD7C08B5BB48F5B5CDD4641",
					},
				},
				// {<<"stdout_formatter">>,{pkg,<<"stdout_formatter">>,<<"0.2.3">>},0},
				// {<<"stdout_formatter">>, <<"EC24868D8619757A68F0798357C7190807A1CFC42CE90C18C23760E59249A21A">>},
				// {<<"stdout_formatter">>, <<"6B9CAAD8930006F9BB35680C5D3311917AC67690C3AF1BA018623324C015ABE5">>},
				{
					Name:     "stdout_formatter",
					Version:  "0.2.3",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/stdout_formatter@0.2.3",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "stdout_formatter",
						Version:    "0.2.3",
						PkgHash:    "EC24868D8619757A68F0798357C7190807A1CFC42CE90C18C23760E59249A21A",
						PkgHashExt: "6B9CAAD8930006F9BB35680C5D3311917AC67690C3AF1BA018623324C015ABE5",
					},
				},
				// {<<"swc">>,
				//  {git,"https://github.com/vernemq/ServerWideClocks.git",
				//       {ref,"4835239dca5a5f4ac7202dd94d7effcaa617d575"}},
				//  0},
				{
					Name:     "swc",
					Version:  "4835239dca5a5f4ac7202dd94d7effcaa617d575",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/swc@4835239dca5a5f4ac7202dd94d7effcaa617d575",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:    "swc",
						Version: "4835239dca5a5f4ac7202dd94d7effcaa617d575",
					},
				},
				// {<<"syslog">>,{pkg,<<"syslog">>,<<"1.1.0">>},0},
				// {<<"syslog">>, <<"6419A232BEA84F07B56DC575225007FFE34D9FDC91ABE6F1B2F254FD71D8EFC2">>},
				// {<<"syslog">>, <<"4C6A41373C7E20587BE33EF841D3DE6F3BEBA08519809329ECC4D27B15B659E1">>},
				{
					Name:     "syslog",
					Version:  "1.1.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/syslog@1.1.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "syslog",
						Version:    "1.1.0",
						PkgHash:    "6419A232BEA84F07B56DC575225007FFE34D9FDC91ABE6F1B2F254FD71D8EFC2",
						PkgHashExt: "4C6A41373C7E20587BE33EF841D3DE6F3BEBA08519809329ECC4D27B15B659E1",
					},
				},
				// {<<"unicode_util_compat">>,{pkg,<<"unicode_util_compat">>,<<"0.7.0">>},1},
				// {<<"unicode_util_compat">>, <<"BC84380C9AB48177092F43AC89E4DFA2C6D62B40B8BD132B1059ECC7232F9A78">>}]},
				// {<<"unicode_util_compat">>, <<"25EEE6D67DF61960CF6A794239566599B09E17E668D3700247BC498638152521">>}]}
				{
					Name:     "unicode_util_compat",
					Version:  "0.7.0",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/unicode_util_compat@0.7.0",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:       "unicode_util_compat",
						Version:    "0.7.0",
						PkgHash:    "BC84380C9AB48177092F43AC89E4DFA2C6D62B40B8BD132B1059ECC7232F9A78",
						PkgHashExt: "25EEE6D67DF61960CF6A794239566599B09E17E668D3700247BC498638152521",
					},
				},
				// {<<"vernemq_dev">>,
				//  {git,"https://github.com/vernemq/vernemq_dev.git",
				//       {ref,"6d622aa8c901ae7777433aef2bd049e380c474a6"}},
				//  0}]}.
				{
					Name:     "vernemq_dev",
					Version:  "6d622aa8c901ae7777433aef2bd049e380c474a6",
					Language: pkg.Erlang,
					Type:     pkg.HexPkg,
					PURL:     "pkg:hex/vernemq_dev@6d622aa8c901ae7777433aef2bd049e380c474a6",
					Metadata: pkg.ErlangRebarLockEntry{
						Name:    "vernemq_dev",
						Version: "6d622aa8c901ae7777433aef2bd049e380c474a6",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			// TODO: relationships are not under test
			var expectedRelationships []artifact.Relationship

			for idx := range test.expected {
				test.expected[idx].Locations = file.NewLocationSet(file.NewLocation(test.fixture))
			}

			pkgtest.TestFileParser(t, test.fixture, parseRebarLock, test.expected, expectedRelationships)
		})
	}
}

func Test_corruptRebarLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/rebar.lock").
		WithError().
		TestParser(t, parseRebarLock)
}
