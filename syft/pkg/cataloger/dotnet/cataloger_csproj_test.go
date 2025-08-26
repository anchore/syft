package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestDotnetCsprojCataloger(t *testing.T) {
	fixture := "test-fixtures/weatherforecast-steeltoe"
	
	expectedLocation := file.NewLocation("Sample.csproj")
	fixtureLocationSet := file.NewLocationSet(expectedLocation)

	expected := []pkg.Package{
		{
			Name:      "Steeltoe.Common.Hosting",
			Version:   "3.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Common.Hosting@3.2.%2A",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Steeltoe.Common.Hosting",
				Version:  "3.2.*",
				Path:     ".",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Steeltoe.Management.EndpointCore",
			Version:   "3.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Management.EndpointCore@3.2.%2A",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Steeltoe.Management.EndpointCore",
				Version:  "3.2.*",
				Path:     ".",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Swashbuckle.AspNetCore",
			Version:   "6.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Swashbuckle.AspNetCore@6.2.%2A",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Swashbuckle.AspNetCore",
				Version:  "6.2.*",
				Path:     ".",
				Sha512:   "",
				HashPath: "",
			},
		},
	}

	pkgtest.TestCataloger(t, fixture, NewDotnetCsprojCataloger(), expected, nil)
}

func TestDotnetCsprojCataloger_GlopsMatch(t *testing.T) {
	expectedPackages := []pkg.Package{
		{
			Name:      "Steeltoe.Common.Hosting",
			Version:   "3.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Common.Hosting@3.2.%2A",
			Locations: file.NewLocationSet(file.NewLocation("Sample.csproj")),
			Metadata: pkg.DotnetDepsEntry{
				Name:    "Steeltoe.Common.Hosting",
				Version: "3.2.*",
				Path:    ".",
				Sha512:  "",
				HashPath: "",
			},
		},
		{
			Name:      "Steeltoe.Management.EndpointCore",
			Version:   "3.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Management.EndpointCore@3.2.%2A",
			Locations: file.NewLocationSet(file.NewLocation("Sample.csproj")),
			Metadata: pkg.DotnetDepsEntry{
				Name:    "Steeltoe.Management.EndpointCore",
				Version: "3.2.*",
				Path:    ".",
				Sha512:  "",
				HashPath: "",
			},
		},
		{
			Name:      "Swashbuckle.AspNetCore",
			Version:   "6.2.*",
			FoundBy:   "dotnet-csproj-cataloger",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Swashbuckle.AspNetCore@6.2.%2A",
			Locations: file.NewLocationSet(file.NewLocation("Sample.csproj")),
			Metadata: pkg.DotnetDepsEntry{
				Name:    "Swashbuckle.AspNetCore",
				Version: "6.2.*",
				Path:    ".",
				Sha512:  "",
				HashPath: "",
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/weatherforecast-steeltoe").
		Expects(expectedPackages, nil).
		TestCataloger(t, NewDotnetCsprojCataloger())
}
