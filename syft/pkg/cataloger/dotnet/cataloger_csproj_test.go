package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestDotnetCsprojCataloger(t *testing.T) {
	fixture := "test-fixtures/steeltoe-sample/WeatherForecast.csproj"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "Steeltoe.Discovery.Eureka",
			Version:   "3.2.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Discovery.Eureka@3.2.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Steeltoe.Discovery.Eureka",
				Version:  "3.2.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Steeltoe.Extensions.Configuration.CloudFoundry",
			Version:   "3.2.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Extensions.Configuration.CloudFoundry@3.2.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Steeltoe.Extensions.Configuration.CloudFoundry",
				Version:  "3.2.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Steeltoe.Management.Endpoint",
			Version:   "3.2.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Steeltoe.Management.Endpoint@3.2.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Steeltoe.Management.Endpoint",
				Version:  "3.2.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Microsoft.AspNetCore.OpenApi",
			Version:   "8.0.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Microsoft.AspNetCore.OpenApi@8.0.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Microsoft.AspNetCore.OpenApi",
				Version:  "8.0.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Swashbuckle.AspNetCore",
			Version:   "6.5.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Swashbuckle.AspNetCore@6.5.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Swashbuckle.AspNetCore",
				Version:  "6.5.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Serilog.AspNetCore",
			Version:   "8.0.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Serilog.AspNetCore@8.0.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Serilog.AspNetCore",
				Version:  "8.0.0",
				Path:     "test-fixtures/steeltoe-sample",
				Sha512:   "",
				HashPath: "",
			},
		},
		{
			Name:      "Serilog.Sinks.Console",
			Version:   "5.0.0",
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Serilog.Sinks.Console@5.0.0",
			Locations: fixtureLocationSet,
			Metadata: pkg.DotnetDepsEntry{
				Name:     "Serilog.Sinks.Console",
				Version:  "5.0.0",
				Path:     "test-fixtures/steeltoe-sample",
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
			Name:     "Serilog",
			Version:  "2.10.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Serilog@2.10.0",
		},
		{
			Name:     "Serilog.Sinks.Console",
			Version:  "4.0.1",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Serilog.Sinks.Console@4.0.1",
		},
		{
			Name:     "Newtonsoft.Json",
			Version:  "13.0.3",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
		},
		{
			Name:     "Humanizer",
			Version:  "2.14.1",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Humanizer@2.14.1",
		},
		{
			Name:     "Microsoft.Web.LibraryManager.Build",
			Version:  "2.1.175",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Microsoft.Web.LibraryManager.Build@2.1.175",
		},
		{
			Name:     "Steeltoe.Discovery.Eureka",
			Version:  "3.2.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Steeltoe.Discovery.Eureka@3.2.0",
		},
		{
			Name:     "Steeltoe.Extensions.Configuration.CloudFoundry",
			Version:  "3.2.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Steeltoe.Extensions.Configuration.CloudFoundry@3.2.0",
		},
		{
			Name:     "Steeltoe.Management.Endpoint",
			Version:  "3.2.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Steeltoe.Management.Endpoint@3.2.0",
		},
		{
			Name:     "Microsoft.AspNetCore.OpenApi",
			Version:  "8.0.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Microsoft.AspNetCore.OpenApi@8.0.0",
		},
		{
			Name:     "Swashbuckle.AspNetCore",
			Version:  "6.5.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Swashbuckle.AspNetCore@6.5.0",
		},
		{
			Name:     "Serilog.AspNetCore",
			Version:  "8.0.0",
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/Serilog.AspNetCore@8.0.0",
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures").
		Expects(expectedPackages, nil).
		TestCataloger(t, NewDotnetCsprojCataloger())
}
