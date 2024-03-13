package lua

import (
	// "encoding/json"
	// "fmt"
	// "io"
	// "net/http"s
	// "net/url"
	// "path"
	// "strings"
	// "time"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackageLuaRockPackage(u luaRockPackage, indexLocation file.Location) pkg.Package {
	licenseCandidates := []string{u.License}

	license := pkg.NewLicensesFromLocation(indexLocation, licenseCandidates...)
	p := pkg.Package{
		Name:      u.Name,
		Version:   u.Version,
		PURL:      packageURL(u.Name, u.Version),
		Locations: file.NewLocationSet(indexLocation),
		Language:  pkg.Lua,
		Licenses:  pkg.NewLicenseSet(license...),
		Type:      pkg.LuaRockPkg,
		Metadata: pkg.LuaRockPackage{
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
		packageurl.TypeLuaRock,
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
