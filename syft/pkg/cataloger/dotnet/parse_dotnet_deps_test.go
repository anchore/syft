package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_corruptDotnetDeps(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/something.deps.json").
		WithError().
		TestParser(t, parseDotnetDeps)
}

func TestParseDotnetDeps(t *testing.T) {
	fixture := "test-fixtures/TestLibrary.deps.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))
	rootPkg := pkg.Package{
		Name:      "TestLibrary",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/TestLibrary@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:    "TestLibrary",
			Version: "1.0.0",
		},
	}
	testCommon := pkg.Package{
		Name:      "TestCommon",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/TestCommon@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:    "TestCommon",
			Version: "1.0.0",
		},
	}
	awssdkcore := pkg.Package{
		Name:      "AWSSDK.Core",
		Version:   "3.7.10.6",
		PURL:      "pkg:nuget/AWSSDK.Core@3.7.10.6",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "AWSSDK.Core",
			Version:  "3.7.10.6",
			Sha512:   "sha512-kHBB+QmosVaG6DpngXQ8OlLVVNMzltNITfsRr68Z90qO7dSqJ2EHNd8dtBU1u3AQQLqqFHOY0lfmbpexeH6Pew==",
			Path:     "awssdk.core/3.7.10.6",
			HashPath: "awssdk.core.3.7.10.6.nupkg.sha512",
		},
	}
	msftDependencyInjectionAbstractions := pkg.Package{
		Name:      "Microsoft.Extensions.DependencyInjection.Abstractions",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.DependencyInjection.Abstractions",
			Version:  "6.0.0",
			Sha512:   "sha512-xlzi2IYREJH3/m6+lUrQlujzX8wDitm4QGnUu6kUXTQAWPuZY8i+ticFJbzfqaetLA6KR/rO6Ew/HuYD+bxifg==",
			Path:     "microsoft.extensions.dependencyinjection.abstractions/6.0.0",
			HashPath: "microsoft.extensions.dependencyinjection.abstractions.6.0.0.nupkg.sha512",
		},
	}
	msftDependencyInjection := pkg.Package{
		Name:      "Microsoft.Extensions.DependencyInjection",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.DependencyInjection@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.DependencyInjection",
			Version:  "6.0.0",
			Sha512:   "sha512-k6PWQMuoBDGGHOQTtyois2u4AwyVcIwL2LaSLlTZQm2CYcJ1pxbt6jfAnpWmzENA/wfrYRI/X9DTLoUkE4AsLw==",
			Path:     "microsoft.extensions.dependencyinjection/6.0.0",
			HashPath: "microsoft.extensions.dependencyinjection.6.0.0.nupkg.sha512",
		},
	}
	msftLoggingAbstractions := pkg.Package{
		Name:      "Microsoft.Extensions.Logging.Abstractions",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Logging.Abstractions@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Logging.Abstractions",
			Version:  "6.0.0",
			Sha512:   "sha512-/HggWBbTwy8TgebGSX5DBZ24ndhzi93sHUBDvP1IxbZD7FDokYzdAr6+vbWGjw2XAfR2EJ1sfKUotpjHnFWPxA==",
			Path:     "microsoft.extensions.logging.abstractions/6.0.0",
			HashPath: "microsoft.extensions.logging.abstractions.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsLogging := pkg.Package{
		Name:      "Microsoft.Extensions.Logging",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Logging@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Logging",
			Version:  "6.0.0",
			Sha512:   "sha512-eIbyj40QDg1NDz0HBW0S5f3wrLVnKWnDJ/JtZ+yJDFnDj90VoPuoPmFkeaXrtu+0cKm5GRAwoDf+dBWXK0TUdg==",
			Path:     "microsoft.extensions.logging/6.0.0",
			HashPath: "microsoft.extensions.logging.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsOptions := pkg.Package{
		Name:      "Microsoft.Extensions.Options",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Options@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Options",
			Version:  "6.0.0",
			Sha512:   "sha512-dzXN0+V1AyjOe2xcJ86Qbo233KHuLEY0njf/P2Kw8SfJU+d45HNS2ctJdnEnrWbM9Ye2eFgaC5Mj9otRMU6IsQ==",
			Path:     "microsoft.extensions.options/6.0.0",
			HashPath: "microsoft.extensions.options.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsPrimitives := pkg.Package{
		Name:      "Microsoft.Extensions.Primitives",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Primitives@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Primitives",
			Version:  "6.0.0",
			Sha512:   "sha512-9+PnzmQFfEFNR9J2aDTfJGGupShHjOuGw4VUv+JB044biSHrnmCIMD+mJHmb2H7YryrfBEXDurxQ47gJZdCKNQ==",
			Path:     "microsoft.extensions.primitives/6.0.0",
			HashPath: "microsoft.extensions.primitives.6.0.0.nupkg.sha512",
		},
	}
	newtonsoftJson := pkg.Package{
		Name:      "Newtonsoft.Json",
		Version:   "13.0.1",
		PURL:      "pkg:nuget/Newtonsoft.Json@13.0.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Newtonsoft.Json",
			Version:  "13.0.1",
			Sha512:   "sha512-ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A==",
			Path:     "newtonsoft.json/13.0.1",
			HashPath: "newtonsoft.json.13.0.1.nupkg.sha512",
		},
	}
	serilogSinksConsole := pkg.Package{
		Name:      "Serilog.Sinks.Console",
		Version:   "4.0.1",
		PURL:      "pkg:nuget/Serilog.Sinks.Console@4.0.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Serilog.Sinks.Console",
			Version:  "4.0.1",
			Sha512:   "sha512-apLOvSJQLlIbKlbx+Y2UDHSP05kJsV7mou+fvJoRGs/iR+jC22r8cuFVMjjfVxz/AD4B2UCltFhE1naRLXwKNw==",
			Path:     "serilog.sinks.console/4.0.1",
			HashPath: "serilog.sinks.console.4.0.1.nupkg.sha512",
		},
	}
	serilog := pkg.Package{
		Name:      "Serilog",
		Version:   "2.10.0",
		PURL:      "pkg:nuget/Serilog@2.10.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Serilog",
			Version:  "2.10.0",
			Sha512:   "sha512-+QX0hmf37a0/OZLxM3wL7V6/ADvC1XihXN4Kq/p6d8lCPfgkRdiuhbWlMaFjR9Av0dy5F0+MBeDmDdRZN/YwQA==",
			Path:     "serilog/2.10.0",
			HashPath: "serilog.2.10.0.nupkg.sha512",
		},
	}
	systemDiagnosticsDiagnosticsource := pkg.Package{
		Name:      "System.Diagnostics.DiagnosticSource",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/System.Diagnostics.DiagnosticSource@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "System.Diagnostics.DiagnosticSource",
			Version:  "6.0.0",
			Sha512:   "sha512-frQDfv0rl209cKm1lnwTgFPzNigy2EKk1BS3uAvHvlBVKe5cymGyHO+Sj+NLv5VF/AhHsqPIUUwya5oV4CHMUw==",
			Path:     "system.diagnostics.diagnosticsource/6.0.0",
			HashPath: "system.diagnostics.diagnosticsource.6.0.0.nupkg.sha512",
		},
	}
	systemRuntimeCompilerServicesUnsafe := pkg.Package{
		Name:      "System.Runtime.CompilerServices.Unsafe",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/System.Runtime.CompilerServices.Unsafe@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "System.Runtime.CompilerServices.Unsafe",
			Version:  "6.0.0",
			Sha512:   "sha512-/iUeP3tq1S0XdNNoMz5C9twLSrM/TH+qElHkXWaPvuNOt+99G75NrV0OS2EqHx5wMN7popYjpc8oTjC1y16DLg==",
			Path:     "system.runtime.compilerservices.unsafe/6.0.0",
			HashPath: "system.runtime.compilerservices.unsafe.6.0.0.nupkg.sha512",
		}}

	expectedPkgs := []pkg.Package{
		awssdkcore,
		msftDependencyInjection,
		msftDependencyInjectionAbstractions,
		msftExtensionsLogging,
		msftLoggingAbstractions,
		msftExtensionsOptions,
		msftExtensionsPrimitives,
		newtonsoftJson,
		serilog,
		serilogSinksConsole,
		systemDiagnosticsDiagnosticsource,
		systemRuntimeCompilerServicesUnsafe,
		testCommon,
		rootPkg,
	}

	// ┌── (✓ = is represented in the test)
	// ↓
	//
	// ✓ TestLibrary/1.0.0 (project)
	// ✓  ├── [a] Microsoft.Extensions.DependencyInjection/6.0.0                     [file version: 6.0.21.52210]
	// ✓  │    ├── [b] Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0   [file version: 6.0.21.52210]
	// ✓  │    └── [c!] System.Runtime.CompilerServices.Unsafe/6.0.0                 [NO TARGET INFO]
	// ✓  ├── Microsoft.Extensions.Logging/6.0.0                                     [file version: 6.0.21.52210]
	// ✓  │    ├── Microsoft.Extensions.DependencyInjection/6.0.0                    ...to [a]
	// ✓  │    ├── Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0       ...to [b]
	// ✓  │    ├── Microsoft.Extensions.Logging.Abstractions/6.0.0                   [file version: 6.0.21.52210]
	// ✓  │    ├── Microsoft.Extensions.Options/6.0.0                                [file version: 6.0.21.52210]
	// ✓  │    │    ├── Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0  ...to [b]
	// ✓  │    │    └── Microsoft.Extensions.Primitives/6.0.0                        [file version: 6.0.21.52210]
	// ✓  │    │         └── System.Runtime.CompilerServices.Unsafe/6.0.0            ...to [c!]
	// ✓  │    └── System.Diagnostics.DiagnosticSource/6.0.0                         [NO RUNTIME INFO]
	// ✓  │         └── System.Runtime.CompilerServices.Unsafe/6.0.0                 ...to [c!]
	// ✓  ├── Newtonsoft.Json/13.0.1                                                 [file version: 13.0.1.25517]
	// ✓  ├── [d] Serilog/2.10.0                                                     [file version: 2.10.0.0]
	// ✓  ├── Serilog.Sinks.Console/4.0.1                                            [file version: 4.0.1.0]
	// ✓  │    └── Serilog/2.10.0                                                    ...to [d]
	// ✓  └── [e!] TestCommon/1.0.0                                                  [NOT SERVICEABLE / NO SHA]
	// ✓       └── AWSSDK.Core/3.7.10.6                                              [file version: 3.7.10.6]

	expectedRelationships := []artifact.Relationship{
		{
			From: awssdkcore,
			To:   testCommon,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjection,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjection,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftDependencyInjection,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftExtensionsOptions,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsLogging,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftLoggingAbstractions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsOptions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsPrimitives,
			To:   msftExtensionsOptions,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: newtonsoftJson,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilog,
			To:   serilogSinksConsole,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilog,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilogSinksConsole,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemDiagnosticsDiagnosticsource,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   msftDependencyInjection,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   msftExtensionsPrimitives,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   systemDiagnosticsDiagnosticsource,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: testCommon,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseDotnetDeps, expectedPkgs, expectedRelationships)
}
