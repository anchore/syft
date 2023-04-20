package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDotnetDeps(t *testing.T) {
	fixture := "test-fixtures/TestLibrary.deps.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))
	expected := []pkg.Package{
		{
			Name:         "AWSSDK.Core",
			Version:      "3.7.10.6",
			PURL:         "pkg:nuget/AWSSDK.Core@3.7.10.6",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "AWSSDK.Core",
				Version:  "3.7.10.6",
				Sha512:   "sha512-kHBB+QmosVaG6DpngXQ8OlLVVNMzltNITfsRr68Z90qO7dSqJ2EHNd8dtBU1u3AQQLqqFHOY0lfmbpexeH6Pew==",
				Path:     "awssdk.core/3.7.10.6",
				HashPath: "awssdk.core.3.7.10.6.nupkg.sha512",
			},
		},
		{
			Name:         "Microsoft.Extensions.DependencyInjection.Abstractions",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.DependencyInjection.Abstractions",
				Version:  "6.0.0",
				Sha512:   "sha512-xlzi2IYREJH3/m6+lUrQlujzX8wDitm4QGnUu6kUXTQAWPuZY8i+ticFJbzfqaetLA6KR/rO6Ew/HuYD+bxifg==",
				Path:     "microsoft.extensions.dependencyinjection.abstractions/6.0.0",
				HashPath: "microsoft.extensions.dependencyinjection.abstractions.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "Microsoft.Extensions.DependencyInjection",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.DependencyInjection@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.DependencyInjection",
				Version:  "6.0.0",
				Sha512:   "sha512-k6PWQMuoBDGGHOQTtyois2u4AwyVcIwL2LaSLlTZQm2CYcJ1pxbt6jfAnpWmzENA/wfrYRI/X9DTLoUkE4AsLw==",
				Path:     "microsoft.extensions.dependencyinjection/6.0.0",
				HashPath: "microsoft.extensions.dependencyinjection.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "Microsoft.Extensions.Logging.Abstractions",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.Logging.Abstractions@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.Logging.Abstractions",
				Version:  "6.0.0",
				Sha512:   "sha512-/HggWBbTwy8TgebGSX5DBZ24ndhzi93sHUBDvP1IxbZD7FDokYzdAr6+vbWGjw2XAfR2EJ1sfKUotpjHnFWPxA==",
				Path:     "microsoft.extensions.logging.abstractions/6.0.0",
				HashPath: "microsoft.extensions.logging.abstractions.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "Microsoft.Extensions.Logging",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.Logging@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.Logging",
				Version:  "6.0.0",
				Sha512:   "sha512-eIbyj40QDg1NDz0HBW0S5f3wrLVnKWnDJ/JtZ+yJDFnDj90VoPuoPmFkeaXrtu+0cKm5GRAwoDf+dBWXK0TUdg==",
				Path:     "microsoft.extensions.logging/6.0.0",
				HashPath: "microsoft.extensions.logging.6.0.0.nupkg.sha512",
			},
		},

		{
			Name:         "Microsoft.Extensions.Options",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.Options@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.Options",
				Version:  "6.0.0",
				Sha512:   "sha512-dzXN0+V1AyjOe2xcJ86Qbo233KHuLEY0njf/P2Kw8SfJU+d45HNS2ctJdnEnrWbM9Ye2eFgaC5Mj9otRMU6IsQ==",
				Path:     "microsoft.extensions.options/6.0.0",
				HashPath: "microsoft.extensions.options.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "Microsoft.Extensions.Primitives",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/Microsoft.Extensions.Primitives@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Microsoft.Extensions.Primitives",
				Version:  "6.0.0",
				Sha512:   "sha512-9+PnzmQFfEFNR9J2aDTfJGGupShHjOuGw4VUv+JB044biSHrnmCIMD+mJHmb2H7YryrfBEXDurxQ47gJZdCKNQ==",
				Path:     "microsoft.extensions.primitives/6.0.0",
				HashPath: "microsoft.extensions.primitives.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "Newtonsoft.Json",
			Version:      "13.0.1",
			PURL:         "pkg:nuget/Newtonsoft.Json@13.0.1",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Newtonsoft.Json",
				Version:  "13.0.1",
				Sha512:   "sha512-ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A==",
				Path:     "newtonsoft.json/13.0.1",
				HashPath: "newtonsoft.json.13.0.1.nupkg.sha512",
			},
		},
		{
			Name:         "Serilog.Sinks.Console",
			Version:      "4.0.1",
			PURL:         "pkg:nuget/Serilog.Sinks.Console@4.0.1",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Serilog.Sinks.Console",
				Version:  "4.0.1",
				Sha512:   "sha512-apLOvSJQLlIbKlbx+Y2UDHSP05kJsV7mou+fvJoRGs/iR+jC22r8cuFVMjjfVxz/AD4B2UCltFhE1naRLXwKNw==",
				Path:     "serilog.sinks.console/4.0.1",
				HashPath: "serilog.sinks.console.4.0.1.nupkg.sha512",
			},
		},
		{
			Name:         "Serilog",
			Version:      "2.10.0",
			PURL:         "pkg:nuget/Serilog@2.10.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "Serilog",
				Version:  "2.10.0",
				Sha512:   "sha512-+QX0hmf37a0/OZLxM3wL7V6/ADvC1XihXN4Kq/p6d8lCPfgkRdiuhbWlMaFjR9Av0dy5F0+MBeDmDdRZN/YwQA==",
				Path:     "serilog/2.10.0",
				HashPath: "serilog.2.10.0.nupkg.sha512",
			},
		},
		{
			Name:         "System.Diagnostics.DiagnosticSource",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/System.Diagnostics.DiagnosticSource@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "System.Diagnostics.DiagnosticSource",
				Version:  "6.0.0",
				Sha512:   "sha512-frQDfv0rl209cKm1lnwTgFPzNigy2EKk1BS3uAvHvlBVKe5cymGyHO+Sj+NLv5VF/AhHsqPIUUwya5oV4CHMUw==",
				Path:     "system.diagnostics.diagnosticsource/6.0.0",
				HashPath: "system.diagnostics.diagnosticsource.6.0.0.nupkg.sha512",
			},
		},
		{
			Name:         "System.Runtime.CompilerServices.Unsafe",
			Version:      "6.0.0",
			PURL:         "pkg:nuget/System.Runtime.CompilerServices.Unsafe@6.0.0",
			Locations:    fixtureLocationSet,
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:     "System.Runtime.CompilerServices.Unsafe",
				Version:  "6.0.0",
				Sha512:   "sha512-/iUeP3tq1S0XdNNoMz5C9twLSrM/TH+qElHkXWaPvuNOt+99G75NrV0OS2EqHx5wMN7popYjpc8oTjC1y16DLg==",
				Path:     "system.runtime.compilerservices.unsafe/6.0.0",
				HashPath: "system.runtime.compilerservices.unsafe.6.0.0.nupkg.sha512",
			},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseDotnetDeps, expected, expectedRelationships)
}
