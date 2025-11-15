package lua

import (
	"context"
	"path"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

func newLuaRocksPackage(ctx context.Context, resolver file.Resolver, u luaRocksPackage, indexLocation file.Location) pkg.Package {
	license := pkg.NewLicensesFromLocationWithContext(ctx, indexLocation, u.License)
	if len(license) == 0 {
		license = licenses.FindInDirs(ctx, resolver, path.Dir(indexLocation.Path()))
	}
	p := pkg.Package{
		Name:      u.Name,
		Version:   u.Version,
		PURL:      packageURL(u.Name, u.Version),
		Locations: file.NewLocationSet(indexLocation),
		Language:  pkg.Lua,
		Licenses:  pkg.NewLicenseSet(license...),
		Type:      pkg.LuaRocksPkg,
		Metadata: pkg.LuaRocksPackage{
			Name:         u.Name,
			Version:      u.Version,
			License:      u.License,
			Homepage:     u.Homepage,
			Description:  u.Description,
			URL:          u.Repository.URL,
			Dependencies: u.Dependencies,
		},
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Lua Rock package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeLuaRocks,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
