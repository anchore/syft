package lua

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"testing"
)

func TestParseRockspec(t *testing.T) {
	tests := []struct {
		Fixture     string
		ExpectedPkg pkg.Package
	}{
		{
			Fixture: "test-fixtures/rockspec/kong-3.7.0-0.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "kong",
				Version:  "3.7.0-0",
				PURL:     "pkg:luarock/kong@3.7.0-0",
				Type:     pkg.LuaRockPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("Apache-2.0", file.NewLocation("test-fixtures/rockspec/kong-3.7.0-0.rockspec")),
				),
				Metadata: pkg.LuaRockPackage{
					Name:        "kong",
					Version:     "3.7.0-0",
					License:     "Apache-2.0",
					Homepage:    "https://konghq.com",
					Description: "Kong is a scalable and customizable API Management Layer built on top of Nginx.",
					URL:         "git+https://github.com/Kong/kong.git",
				},
			},
		},
		{
			Fixture: "test-fixtures/rockspec/lpeg-1.0.2-1.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "LPeg",
				Version:  "1.0.2-1",
				PURL:     "pkg:luarock/LPeg@1.0.2-1",
				Type:     pkg.LuaRockPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("MIT/X11", file.NewLocation("test-fixtures/rockspec/lpeg-1.0.2-1.rockspec")),
				),
				Metadata: pkg.LuaRockPackage{
					Name:        "LPeg",
					Version:     "1.0.2-1",
					License:     "MIT/X11",
					Homepage:    "http://www.inf.puc-rio.br/~roberto/lpeg.html",
					Description: "Parsing Expression Grammars For Lua",
					URL:         "http://www.inf.puc-rio.br/~roberto/lpeg/lpeg-1.0.2.tar.gz",
				},
			},
		},
		{
			Fixture: "test-fixtures/rockspec/kong-pgmoon-1.16.2-1.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "kong-pgmoon",
				Version:  "1.16.2-1",
				PURL:     "pkg:luarock/kong-pgmoon@1.16.2-1",
				Type:     pkg.LuaRockPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocations("MIT", file.NewLocation("test-fixtures/rockspec/kong-pgmoon-1.16.2-1.rockspec")),
				),
				Metadata: pkg.LuaRockPackage{
					Name:        "kong-pgmoon",
					Version:     "1.16.2-1",
					License:     "MIT",
					Homepage:    "https://github.com/Kong/pgmoon",
					Description: "Postgres driver for OpenResty and Lua",
					URL:         "git+https://github.com/kong/pgmoon.git",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			test.ExpectedPkg.Locations.Add(file.NewLocation(test.Fixture))
			pkgtest.TestFileParser(t, test.Fixture, parseRockspec, []pkg.Package{test.ExpectedPkg}, nil)
		})
	}
}
