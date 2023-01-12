package erlang

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRebarLock(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:         "certifi",
			Version:      "2.9.0",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/certifi@2.9.0",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "certifi",
				Version:    "2.9.0",
				PkgHash:    "6F2A475689DD47F19FB74334859D460A2DC4E3252A3324BD2111B8F0429E7E21",
				PkgHashExt: "266DA46BDB06D6C6D35FDE799BCB28D36D985D424AD7C08B5BB48F5B5CDD4641",
			},
		},
		{
			Name:         "idna",
			Version:      "6.1.1",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/idna@6.1.1",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "idna",
				Version:    "6.1.1",
				PkgHash:    "8A63070E9F7D0C62EB9D9FCB360A7DE382448200FBBD1B106CC96D3D8099DF8D",
				PkgHashExt: "92376EB7894412ED19AC475E4A86F7B413C1B9FBB5BD16DCCD57934157944CEA",
			},
		},
		{
			Name:         "metrics",
			Version:      "1.0.1",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/metrics@1.0.1",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "metrics",
				Version:    "1.0.1",
				PkgHash:    "25F094DEA2CDA98213CECC3AEFF09E940299D950904393B2A29D191C346A8486",
				PkgHashExt: "69B09ADDDC4F74A40716AE54D140F93BEB0FB8978D8636EADED0C31B6F099F16",
			},
		},
		{
			Name:         "mimerl",
			Version:      "1.2.0",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/mimerl@1.2.0",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "mimerl",
				Version:    "1.2.0",
				PkgHash:    "67E2D3F571088D5CFD3E550C383094B47159F3EEE8FFA08E64106CDF5E981BE3",
				PkgHashExt: "F278585650AA581986264638EBF698F8BB19DF297F66AD91B18910DFC6E19323",
			},
		},
		{
			Name:         "parse_trans",
			Version:      "3.3.1",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/parse_trans@3.3.1",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "parse_trans",
				Version:    "3.3.1",
				PkgHash:    "16328AB840CC09919BD10DAB29E431DA3AF9E9E7E7E6F0089DD5A2D2820011D8",
				PkgHashExt: "07CD9577885F56362D414E8C4C4E6BDF10D43A8767ABB92D24CBE8B24C54888B",
			},
		},
		{
			Name:         "ssl_verify_fun",
			Version:      "1.1.6",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/ssl_verify_fun@1.1.6",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "ssl_verify_fun",
				Version:    "1.1.6",
				PkgHash:    "CF344F5692C82D2CD7554F5EC8FD961548D4FD09E7D22F5B62482E5AEAEBD4B0",
				PkgHashExt: "BDB0D2471F453C88FF3908E7686F86F9BE327D065CC1EC16FA4540197EA04680",
			},
		},
		{
			Name:         "unicode_util_compat",
			Version:      "0.7.0",
			Language:     pkg.Erlang,
			Type:         pkg.HexPkg,
			PURL:         "pkg:hex/unicode_util_compat@0.7.0",
			MetadataType: pkg.RebarLockMetadataType,
			Metadata: pkg.RebarLockMetadata{
				Name:       "unicode_util_compat",
				Version:    "0.7.0",
				PkgHash:    "BC84380C9AB48177092F43AC89E4DFA2C6D62B40B8BD132B1059ECC7232F9A78",
				PkgHashExt: "25EEE6D67DF61960CF6A794239566599B09E17E668D3700247BC498638152521",
			},
		},
	}

	fixture := "test-fixtures/rebar.lock"

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseRebarLock, expected, expectedRelationships)
}
