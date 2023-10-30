package elixir

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseMixLock(t *testing.T) {
	locations := file.NewLocationSet(file.NewLocation("test-fixtures/mix.lock"))
	expected := []pkg.Package{
		{
			Name:      "castore",
			Version:   "0.1.17",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/castore@0.1.17",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "castore",
				Version:    "0.1.17",
				PkgHash:    "ba672681de4e51ed8ec1f74ed624d104c0db72742ea1a5e74edbc770c815182f",
				PkgHashExt: "d9844227ed52d26e7519224525cb6868650c272d4a3d327ce3ca5570c12163f9",
			},
		},
		{
			Name:      "connection",
			Version:   "1.1.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/connection@1.1.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "connection",
				Version:    "1.1.0",
				PkgHash:    "ff2a49c4b75b6fb3e674bfc5536451607270aac754ffd1bdfe175abe4a6d7a68",
				PkgHashExt: "722c1eb0a418fbe91ba7bd59a47e28008a189d47e37e0e7bb85585a016b2869c",
			},
		},
		{
			Name:      "cowboy",
			Version:   "2.9.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/cowboy@2.9.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "cowboy",
				Version:    "2.9.0",
				PkgHash:    "865dd8b6607e14cf03282e10e934023a1bd8be6f6bacf921a7e2a96d800cd452",
				PkgHashExt: "2c729f934b4e1aa149aff882f57c6372c15399a20d54f65c8d67bef583021bde",
			},
		},
		{
			Name:      "cowboy_telemetry",
			Version:   "0.4.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/cowboy_telemetry@0.4.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "cowboy_telemetry",
				Version:    "0.4.0",
				PkgHash:    "f239f68b588efa7707abce16a84d0d2acf3a0f50571f8bb7f56a15865aae820c",
				PkgHashExt: "7d98bac1ee4565d31b62d59f8823dfd8356a169e7fcbb83831b8a5397404c9de",
			},
		},
		{
			Name:      "cowlib",
			Version:   "2.11.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/cowlib@2.11.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "cowlib",
				Version:    "2.11.0",
				PkgHash:    "0b9ff9c346629256c42ebe1eeb769a83c6cb771a6ee5960bd110ab0b9b872063",
				PkgHashExt: "2b3e9da0b21c4565751a6d4901c20d1b4cc25cbb7fd50d91d2ab6dd287bc86a9",
			},
		},
		{
			Name:      "db_connection",
			Version:   "2.4.2",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/db_connection@2.4.2",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "db_connection",
				Version:    "2.4.2",
				PkgHash:    "f92e79aff2375299a16bcb069a14ee8615c3414863a6fef93156aee8e86c2ff3",
				PkgHashExt: "4fe53ca91b99f55ea249693a0229356a08f4d1a7931d8ffa79289b145fe83668",
			},
		},
		{
			Name:      "decimal",
			Version:   "2.0.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/decimal@2.0.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "decimal",
				Version:    "2.0.0",
				PkgHash:    "a78296e617b0f5dd4c6caf57c714431347912ffb1d0842e998e9792b5642d697",
				PkgHashExt: "34666e9c55dea81013e77d9d87370fe6cb6291d1ef32f46a1600230b1d44f577",
			},
		},
		{
			Name:      "earmark_parser",
			Version:   "1.4.25",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/earmark_parser@1.4.25",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "earmark_parser",
				Version:    "1.4.25",
				PkgHash:    "2024618731c55ebfcc5439d756852ec4e85978a39d0d58593763924d9a15916f",
				PkgHashExt: "56749c5e1c59447f7b7a23ddb235e4b3defe276afc220a6227237f3efe83f51e",
			},
		},
		{
			Name:      "ecto",
			Version:   "3.8.1",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/ecto@3.8.1",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "ecto",
				Version:    "3.8.1",
				PkgHash:    "35e0bd8c8eb772e14a5191a538cd079706ecb45164ea08a7523b4fc69ab70f56",
				PkgHashExt: "f1b68f8d5fe3ab89e24f57c03db5b5d0aed3602077972098b3a6006a1be4b69b",
			},
		},
		{
			Name:      "ecto_sql",
			Version:   "3.8.1",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/ecto_sql@3.8.1",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "ecto_sql",
				Version:    "3.8.1",
				PkgHash:    "1acaaba32ca0551fd19e492fc7c80414e72fc1a7140fc9395aaa53c2e8629798",
				PkgHashExt: "ba7fc75882edce6f2ceca047315d5db27ead773cafea47f1724e35f1e7964525",
			},
		},
		{
			Name:      "esbuild",
			Version:   "0.5.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/esbuild@0.5.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "esbuild",
				Version:    "0.5.0",
				PkgHash:    "d5bb08ff049d7880ee3609ed5c4b864bd2f46445ea40b16b4acead724fb4c4a3",
				PkgHashExt: "f183a0b332d963c4cfaf585477695ea59eef9a6f2204fdd0efa00e099694ffe5",
			},
		},
		{
			Name:      "ex_doc",
			Version:   "0.28.4",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/ex_doc@0.28.4",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "ex_doc",
				Version:    "0.28.4",
				PkgHash:    "001a0ea6beac2f810f1abc3dbf4b123e9593eaa5f00dd13ded024eae7c523298",
				PkgHashExt: "bf85d003dd34911d89c8ddb8bda1a958af3471a274a4c2150a9c01c78ac3f8ed",
			},
		},
		{
			Name:      "gettext",
			Version:   "0.19.1",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/gettext@0.19.1",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "gettext",
				Version:    "0.19.1",
				PkgHash:    "564953fd21f29358e68b91634799d9d26989f8d039d7512622efb3c3b1c97892",
				PkgHashExt: "10c656c0912b8299adba9b061c06947511e3f109ab0d18b44a866a4498e77222",
			},
		},
		{
			Name:      "hpax",
			Version:   "0.1.1",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/hpax@0.1.1",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "hpax",
				Version:    "0.1.1",
				PkgHash:    "2396c313683ada39e98c20a75a82911592b47e5c24391363343bde74f82396ca",
				PkgHashExt: "0ae7d5a0b04a8a60caf7a39fcf3ec476f35cc2cc16c05abea730d3ce6ac6c826",
			},
		},
		{
			Name:      "jason",
			Version:   "1.3.0",
			Language:  pkg.Elixir,
			Type:      pkg.HexPkg,
			Locations: locations,
			PURL:      "pkg:hex/jason@1.3.0",
			Metadata: pkg.ElixirMixLockEntry{
				Name:       "jason",
				Version:    "1.3.0",
				PkgHash:    "fa6b82a934feb176263ad2df0dbd91bf633d4a46ebfdffea0c8ae82953714946",
				PkgHashExt: "53fc1f51255390e0ec7e50f9cb41e751c260d065dcba2bf0d08dc51a4002c2ac",
			},
		},
	}

	fixture := "test-fixtures/mix.lock"

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseMixLock, expected, expectedRelationships)
}
