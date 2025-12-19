package lua

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRockspec(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		Fixture     string
		ExpectedPkg pkg.Package
	}{
		{
			Fixture: "test-fixtures/rockspec/kong-3.7.0-0.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "kong",
				Version:  "3.7.0-0",
				PURL:     "pkg:luarocks/kong@3.7.0-0",
				Type:     pkg.LuaRocksPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "Apache-2.0", file.NewLocation("test-fixtures/rockspec/kong-3.7.0-0.rockspec")),
				),
				Metadata: pkg.LuaRocksPackage{
					Name:        "kong",
					Version:     "3.7.0-0",
					License:     "Apache-2.0",
					Homepage:    "https://konghq.com",
					Description: "Kong is a scalable and customizable API Management Layer built on top of Nginx.",
					URL:         "git+https://github.com/Kong/kong.git",
					Dependencies: map[string]string{
						"inspect":               "== 3.1.3",
						"luasec":                "== 1.3.2",
						"luasocket":             "== 3.0-rc1",
						"penlight":              "== 1.13.1",
						"lua-resty-http":        "== 0.17.1",
						"lua-resty-jit-uuid":    "== 0.0.7",
						"lua-ffi-zlib":          "== 0.6",
						"multipart":             "== 0.5.9",
						"version":               "== 1.0.1",
						"kong-lapis":            "== 1.16.0.1",
						"kong-pgmoon":           "== 1.16.2",
						"luatz":                 "== 0.4",
						"lua_system_constants":  "== 0.1.4",
						"lyaml":                 "== 6.2.8",
						"luasyslog":             "== 2.0.1",
						"lua_pack":              "== 2.0.0",
						"binaryheap":            ">= 0.4",
						"luaxxhash":             ">= 1.0",
						"lua-protobuf":          "== 0.5.0",
						"lua-resty-healthcheck": "== 3.0.1",
						"lua-messagepack":       "== 0.5.4",
						"lua-resty-aws":         "== 1.3.6",
						"lua-resty-openssl":     "== 1.2.0",
						"lua-resty-counter":     "== 0.2.1",
						"lua-resty-ipmatcher":   "== 0.6.1",
						"lua-resty-acme":        "== 0.12.0",
						"lua-resty-session":     "== 4.0.5",
						"lua-resty-timer-ng":    "== 0.2.6",
						"lpeg":                  "== 1.1.0",
						"lua-resty-ljsonschema": "== 1.1.6-2",
					},
				},
			},
		},
		{
			Fixture: "test-fixtures/rockspec/lpeg-1.0.2-1.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "LPeg",
				Version:  "1.0.2-1",
				PURL:     "pkg:luarocks/LPeg@1.0.2-1",
				Type:     pkg.LuaRocksPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "MIT/X11", file.NewLocation("test-fixtures/rockspec/lpeg-1.0.2-1.rockspec")),
				),
				Metadata: pkg.LuaRocksPackage{
					Name:        "LPeg",
					Version:     "1.0.2-1",
					License:     "MIT/X11",
					Homepage:    "http://www.inf.puc-rio.br/~roberto/lpeg.html",
					Description: "Parsing Expression Grammars For Lua",
					URL:         "http://www.inf.puc-rio.br/~roberto/lpeg/lpeg-1.0.2.tar.gz",
					Dependencies: map[string]string{
						"lua": ">= 5.1",
					},
				},
			},
		},
		{
			Fixture: "test-fixtures/rockspec/kong-pgmoon-1.16.2-1.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "kong-pgmoon",
				Version:  "1.16.2-1",
				PURL:     "pkg:luarocks/kong-pgmoon@1.16.2-1",
				Type:     pkg.LuaRocksPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("test-fixtures/rockspec/kong-pgmoon-1.16.2-1.rockspec")),
				),
				Metadata: pkg.LuaRocksPackage{
					Name:        "kong-pgmoon",
					Version:     "1.16.2-1",
					License:     "MIT",
					Homepage:    "https://github.com/Kong/pgmoon",
					Description: "Postgres driver for OpenResty and Lua",
					URL:         "git+https://github.com/kong/pgmoon.git",
					Dependencies: map[string]string{
						"lua":  ">= 5.1",
						"lpeg": "",
					},
				},
			},
		},
		{
			Fixture: "test-fixtures/rockspec/luasyslog-2.0.1-1.rockspec",
			ExpectedPkg: pkg.Package{
				Name:     "luasyslog",
				Version:  "2.0.1-1",
				PURL:     "pkg:luarocks/luasyslog@2.0.1-1",
				Type:     pkg.LuaRocksPkg,
				Language: pkg.Lua,
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicenseFromLocationsWithContext(ctx, "MIT/X11", file.NewLocation("test-fixtures/rockspec/luasyslog-2.0.1-1.rockspec")),
				),
				Metadata: pkg.LuaRocksPackage{
					Name:        "luasyslog",
					Version:     "2.0.1-1",
					License:     "MIT/X11",
					Homepage:    "https://github.com/lunarmodules/luasyslog",
					Description: "Syslog logging for Lua",
					URL:         "git://github.com/lunarmodules/luasyslog.git",
					Dependencies: map[string]string{
						"lua":        ">= 5.1",
						"lualogging": ">= 1.4.0, < 2.0.0",
					},
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

func Test_corruptRockspec(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/bad-1.23.0-0.rockspec").
		WithError().
		TestParser(t, parseRockspec)
}

func Test_parseDependency(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "dependency with >= constraint",
			input:           "lua >= 5.1",
			expectedName:    "lua",
			expectedVersion: ">= 5.1",
		},
		{
			name:            "dependency with == constraint",
			input:           "inspect == 3.1.3",
			expectedName:    "inspect",
			expectedVersion: "== 3.1.3",
		},
		{
			name:            "dependency without constraint",
			input:           "lpeg",
			expectedName:    "lpeg",
			expectedVersion: "",
		},
		{
			name:            "dependency with complex constraint",
			input:           "lualogging >= 1.4.0, < 2.0.0",
			expectedName:    "lualogging",
			expectedVersion: ">= 1.4.0, < 2.0.0",
		},
		{
			name:            "dependency with version including dash",
			input:           "luasocket == 3.0-rc1",
			expectedName:    "luasocket",
			expectedVersion: "== 3.0-rc1",
		},
		{
			name:            "dependency with extra whitespace",
			input:           "  kong-pgmoon   ==   1.16.2  ",
			expectedName:    "kong-pgmoon",
			expectedVersion: "==   1.16.2",
		},
		{
			name:            "empty string",
			input:           "",
			expectedName:    "",
			expectedVersion: "",
		},
		{
			name:            "whitespace only",
			input:           "   ",
			expectedName:    "",
			expectedVersion: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualName, actualVersion := parseDependency(test.input)
			assert.Equal(t, test.expectedName, actualName)
			assert.Equal(t, test.expectedVersion, actualVersion)
		})
	}
}
